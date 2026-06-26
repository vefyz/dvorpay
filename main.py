"""
ДворPay — веб-панель платёжной системы Дворовой Федерации.
Запуск: uvicorn main:app --reload
"""

from __future__ import annotations

import json
import math
import os
import secrets
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Annotated
from urllib.parse import quote

from fastapi import Depends, FastAPI, Form, HTTPException, Request, status
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel, Field
from sqlalchemy import Boolean, Column, DateTime, Float, Integer, String, create_engine
from sqlalchemy.orm import Session, declarative_base, sessionmaker
from starlette.middleware.sessions import SessionMiddleware

# ---------------------------------------------------------------------------
# Пути и приложение
# ---------------------------------------------------------------------------

BASE_DIR = Path(__file__).resolve().parent


def normalize_database_url(url: str) -> str:
    """Railway/Heroku отдают postgres:// — приводим к драйверу psycopg2."""
    if url.startswith("postgres://"):
        return url.replace("postgres://", "postgresql+psycopg2://", 1)
    if url.startswith("postgresql://") and "+psycopg2" not in url and "+psycopg" not in url:
        return url.replace("postgresql://", "postgresql+psycopg2://", 1)
    return url


DATABASE_URL = normalize_database_url(
    os.getenv("DATABASE_URL", f"sqlite:///{BASE_DIR / 'dvorpay.db'}")
)
SECRET_KEY = os.getenv("SECRET_KEY") or secrets.token_hex(32)

# Учётная запись администратора (единственная при первом запуске)
ADMIN_LOGIN = os.getenv("ADMIN_LOGIN", "admin").strip().lower()
ADMIN_NAME = os.getenv("ADMIN_NAME", "Администрация Двора")
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD", "")

app = FastAPI(title="ДворPay", description="Платёжная система Дворовой Федерации")
app.add_middleware(SessionMiddleware, secret_key=SECRET_KEY)

app.mount("/static", StaticFiles(directory=BASE_DIR / "static"), name="static")
templates = Jinja2Templates(directory=BASE_DIR / "templates")

# ---------------------------------------------------------------------------
# База данных (SQLAlchemy)
# ---------------------------------------------------------------------------

Base = declarative_base()
_engine_kwargs: dict = {}
if DATABASE_URL.startswith("sqlite"):
    _engine_kwargs["connect_args"] = {"check_same_thread": False}
engine = create_engine(DATABASE_URL, **_engine_kwargs)
SessionLocal = sessionmaker(bind=engine, autocommit=False, autoflush=False)


class UserORM(Base):
    """Пользователь системы."""

    __tablename__ = "users"

    id = Column(String, primary_key=True)  # логин
    name = Column(String, nullable=False)
    password = Column(String, nullable=False)  # пароль / ПИН-код
    balance = Column(Float, default=0.0, nullable=False)
    role = Column(String, nullable=False)  # user | business | admin


class TransactionORM(Base):
    """Запись о переводе дублей."""

    __tablename__ = "transactions"

    id = Column(Integer, primary_key=True, autoincrement=True)
    sender_id = Column(String, nullable=False)
    recipient_id = Column(String, nullable=False)
    amount = Column(Float, nullable=False)
    comment = Column(String, default="", nullable=False)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)


class NFCCardORM(Base):
    """NFC-карта (банковский токен) жителя Двора."""

    __tablename__ = "nfc_cards"

    card_token = Column(String, primary_key=True)  # UUID в NFC-чипе
    owner_id = Column(String, nullable=False)
    pin = Column(String, nullable=False)  # 4-значный ПИН
    failed_attempts = Column(Integer, default=0, nullable=False)
    is_blocked = Column(Boolean, default=False, nullable=False)


class DynamicSessionORM(Base):
    """Одноразовая сессия NFC-оплаты (защита от replay)."""

    __tablename__ = "dynamic_sessions"

    session_token = Column(String, primary_key=True)
    card_token = Column(String, nullable=False)
    expires_at = Column(DateTime, nullable=False)
    is_used = Column(Boolean, default=False, nullable=False)


class GeofenceORM(Base):
    """Настройки территории, где разрешена NFC-оплата (круг или полигон)."""

    __tablename__ = "geofence_settings"

    id = Column(Integer, primary_key=True, default=1)
    mode = Column(String, default="circle", nullable=False)  # circle | polygon
    center_lat = Column(Float, nullable=False)
    center_lon = Column(Float, nullable=False)
    radius_meters = Column(Float, default=100.0, nullable=False)
    polygon_json = Column(String, default="[]", nullable=False)  # [[lat, lng], ...]


# ---------------------------------------------------------------------------
# Pydantic-модели (для документации и валидации)
# ---------------------------------------------------------------------------


class User(BaseModel):
    id: str = Field(description="Логин")
    name: str = Field(description="Имя")
    password: str = Field(description="Пароль / ПИН-код")
    balance: float = Field(ge=0, description="Баланс в дублях")
    role: str = Field(description="user | business | admin")


class Transaction(BaseModel):
    id: int
    sender_id: str
    recipient_id: str
    amount: float = Field(gt=0)
    comment: str = ""
    created_at: datetime


# ---------------------------------------------------------------------------
# Конфигурация (геозона, NFC)
# ---------------------------------------------------------------------------

# Геозона Двора по умолчанию (настраивается в админке на карте)
DVOR_CENTER_LAT = 55.751244
DVOR_CENTER_LON = 37.618423
DVOR_RADIUS_METERS = 100.0
NFC_SESSION_TTL_MINUTES = 2
NFC_MAX_PIN_ATTEMPTS = 3


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


DbSession = Annotated[Session, Depends(get_db)]


def validate_admin_password(password: str) -> None:
    """Требования к паролю администратора."""
    if len(password) < 16:
        raise ValueError("ADMIN_PASSWORD: минимум 16 символов")
    if not any(c.isupper() for c in password):
        raise ValueError("ADMIN_PASSWORD: нужна хотя бы одна заглавная буква")
    if not any(c.islower() for c in password):
        raise ValueError("ADMIN_PASSWORD: нужна хотя бы одна строчная буква")
    if not any(c.isdigit() for c in password):
        raise ValueError("ADMIN_PASSWORD: нужна хотя бы одна цифра")
    special = set("!@#$%^&*()-_=+[]{}|;:,.<>?")
    if not any(c in special for c in password):
        raise ValueError("ADMIN_PASSWORD: нужен хотя бы один спецсимвол (!@#$%...)")


def init_db() -> None:
    """Создаёт таблицы. При пустой БД — только один аккаунт admin из env."""
    Base.metadata.create_all(bind=engine)
    db = SessionLocal()
    try:
        if db.query(UserORM).count() == 0:
            if not ADMIN_PASSWORD:
                msg = (
                    "ADMIN_PASSWORD не задан. Укажите сложный пароль в переменных окружения "
                    "(мин. 16 символов, A-z, 0-9, спецсимвол)."
                )
                print(f"ОШИБКА: {msg}")
                if os.getenv("RAILWAY_ENVIRONMENT") or os.getenv("RAILWAY_SERVICE_NAME"):
                    raise RuntimeError(msg)
                return
            validate_admin_password(ADMIN_PASSWORD)
            db.add(
                UserORM(
                    id=ADMIN_LOGIN,
                    name=ADMIN_NAME,
                    password=ADMIN_PASSWORD,
                    balance=0.0,
                    role="admin",
                )
            )
            db.commit()
            print(f"Создан администратор «{ADMIN_LOGIN}». Остальных пользователей добавляйте в админке.")
        if db.query(GeofenceORM).filter(GeofenceORM.id == 1).first() is None:
            db.add(
                GeofenceORM(
                    id=1,
                    mode="circle",
                    center_lat=DVOR_CENTER_LAT,
                    center_lon=DVOR_CENTER_LON,
                    radius_meters=DVOR_RADIUS_METERS,
                    polygon_json="[]",
                )
            )
            db.commit()
    finally:
        db.close()


@app.on_event("startup")
def on_startup() -> None:
    init_db()


# ---------------------------------------------------------------------------
# Вспомогательные функции
# ---------------------------------------------------------------------------

SESSION_USER_KEY = "user_id"


def get_current_user(request: Request, db: Session) -> UserORM | None:
    user_id = request.session.get(SESSION_USER_KEY)
    if not user_id:
        return None
    return db.query(UserORM).filter(UserORM.id == user_id).first()


def require_user(request: Request, db: Session) -> UserORM:
    user = get_current_user(request, db)
    if user is None:
        raise HTTPException(status_code=status.HTTP_303_SEE_OTHER, headers={"Location": "/"})
    return user


def require_admin(request: Request, db: Session) -> UserORM:
    user = require_user(request, db)
    if user.role != "admin":
        raise HTTPException(status_code=status.HTTP_303_SEE_OTHER, headers={"Location": "/dashboard"})
    return user


def get_context_users(db: Session, current_id: str) -> dict:
    """Общие данные для шаблонов: карта имён, список business, контакты."""
    all_users = db.query(UserORM).order_by(UserORM.name).all()
    return {
        "users_map": {u.id: u.name for u in all_users},
        "business_logins": [u.id for u in all_users if u.role == "business"],
        "business_users": [u for u in all_users if u.role == "business"],
        "contacts": [u for u in all_users if u.id != current_id],
        "all_users": all_users,
    }


def redirect_dashboard(error: str | None = None, success: str | None = None, pay: str | None = None) -> RedirectResponse:
    params: list[str] = []
    if error:
        params.append(f"error={error}")
    if success:
        params.append(f"success={success}")
    if pay:
        params.append(f"pay={pay}")
    qs = "&".join(params)
    url = f"/dashboard?{qs}" if qs else "/dashboard"
    return RedirectResponse(url=url, status_code=status.HTTP_303_SEE_OTHER)


def user_transactions(db: Session, user_id: str) -> list[TransactionORM]:
    """Все транзакции, где пользователь — отправитель или получатель."""
    return (
        db.query(TransactionORM)
        .filter(
            (TransactionORM.sender_id == user_id) | (TransactionORM.recipient_id == user_id)
        )
        .order_by(TransactionORM.created_at.desc())
        .all()
    )


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def distance_meters(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
    """Расстояние между GPS-точками (Haversine), метры."""
    earth_radius = 6_371_000.0
    phi1 = math.radians(lat1)
    phi2 = math.radians(lat2)
    d_phi = math.radians(lat2 - lat1)
    d_lambda = math.radians(lon2 - lon1)
    a = (
        math.sin(d_phi / 2) ** 2
        + math.cos(phi1) * math.cos(phi2) * math.sin(d_lambda / 2) ** 2
    )
    return 2 * earth_radius * math.atan2(math.sqrt(a), math.sqrt(1 - a))


def is_inside_dvor(latitude: float, longitude: float, db: Session) -> bool:
    """Проверяет, находится ли точка в разрешённой зоне оплаты (из БД)."""
    gf = get_geofence(db)
    if gf.mode == "polygon":
        polygon = json.loads(gf.polygon_json or "[]")
        if len(polygon) >= 3:
            return point_in_polygon(latitude, longitude, polygon)
    return (
        distance_meters(latitude, longitude, gf.center_lat, gf.center_lon)
        <= gf.radius_meters
    )


def get_geofence(db: Session) -> GeofenceORM:
    """Возвращает настройки геозоны, создаёт дефолтные при отсутствии."""
    row = db.query(GeofenceORM).filter(GeofenceORM.id == 1).first()
    if row is None:
        row = GeofenceORM(
            id=1,
            mode="circle",
            center_lat=DVOR_CENTER_LAT,
            center_lon=DVOR_CENTER_LON,
            radius_meters=DVOR_RADIUS_METERS,
            polygon_json="[]",
        )
        db.add(row)
        db.commit()
        db.refresh(row)
    return row


def geofence_to_dict(gf: GeofenceORM) -> dict:
    """Сериализация геозоны для шаблона / API."""
    polygon = json.loads(gf.polygon_json or "[]")
    return {
        "mode": gf.mode,
        "center_lat": gf.center_lat,
        "center_lon": gf.center_lon,
        "radius_meters": gf.radius_meters,
        "polygon": polygon,
    }


def point_in_polygon(lat: float, lon: float, polygon: list[list[float]]) -> bool:
    """Алгоритм ray casting: точка внутри полигона [[lat, lng], ...]."""
    n = len(polygon)
    if n < 3:
        return False
    inside = False
    j = n - 1
    for i in range(n):
        lati, loni = polygon[i][0], polygon[i][1]
        latj, lonj = polygon[j][0], polygon[j][1]
        if ((loni > lon) != (lonj > lon)) and (
            lat < (latj - lati) * (lon - loni) / (lonj - loni + 1e-12) + lati
        ):
            inside = not inside
        j = i
    return inside


def update_balance(
    db: Session,
    sender_id: str,
    recipient_id: str,
    amount: float,
    comment: str,
) -> None:
    """Списание с отправителя и зачисление получателю + запись в историю."""
    sender = db.query(UserORM).filter(UserORM.id == sender_id).first()
    recipient = db.query(UserORM).filter(UserORM.id == recipient_id).first()
    if sender is None or recipient is None:
        raise ValueError("Пользователь не найден")
    if amount <= 0:
        raise ValueError("Сумма должна быть больше нуля")
    if sender.balance < amount:
        raise ValueError("Недостаточно дублей на балансе")

    sender.balance -= amount
    recipient.balance += amount
    db.add(
        TransactionORM(
            sender_id=sender_id,
            recipient_id=recipient_id,
            amount=amount,
            comment=comment,
        )
    )


def pay_template_context(
    request: Request,
    *,
    error: str | None = None,
    success: str | None = None,
    terminal_mode: bool = False,
    buyer_name: str | None = None,
    session_token: str | None = None,
    merchant=None,
) -> dict:
    return {
        "request": request,
        "error": error,
        "success": success,
        "terminal_mode": terminal_mode,
        "buyer_name": buyer_name,
        "session_token": session_token,
        "merchant": merchant,
    }


# ---------------------------------------------------------------------------
# Маршруты
# ---------------------------------------------------------------------------


@app.get("/", response_class=HTMLResponse)
def login_page(request: Request, db: DbSession):
    """Страница входа."""
    user = get_current_user(request, db)
    if user:
        dest = "/admin" if user.role == "admin" else "/dashboard"
        return RedirectResponse(url=dest, status_code=status.HTTP_303_SEE_OTHER)
    return templates.TemplateResponse(
        request,
        "login.html",
        {"request": request, "error": request.query_params.get("error")},
    )


@app.post("/login")
def login(
    request: Request,
    db: DbSession,
    login: str = Form(...),
    password: str = Form(...),
):
    """Проверка учётных данных и создание сессии."""
    user = db.query(UserORM).filter(UserORM.id == login.strip()).first()
    if user is None or user.password != password:
        return RedirectResponse(
            url="/?error=Неверный+логин+или+пароль",
            status_code=status.HTTP_303_SEE_OTHER,
        )
    request.session[SESSION_USER_KEY] = user.id
    if user.role == "admin":
        return RedirectResponse(url="/admin", status_code=status.HTTP_303_SEE_OTHER)
    return RedirectResponse(url="/dashboard", status_code=status.HTTP_303_SEE_OTHER)


@app.get("/logout")
def logout(request: Request):
    request.session.clear()
    return RedirectResponse(url="/", status_code=status.HTTP_303_SEE_OTHER)


@app.get("/dashboard", response_class=HTMLResponse)
def dashboard(request: Request, db: DbSession):
    """Личный кабинет: баланс, быстрые действия, последние операции."""
    user = get_current_user(request, db)
    if user is None:
        return RedirectResponse(url="/", status_code=status.HTTP_303_SEE_OTHER)
    if user.role == "admin":
        return RedirectResponse(url="/admin", status_code=status.HTTP_303_SEE_OTHER)

    ctx = get_context_users(db, user.id)
    txs = user_transactions(db, user.id)[:5]

    return templates.TemplateResponse(
        request,
        "dashboard.html",
        {
            "request": request,
            "user": user,
            "transactions": txs,
            "active_tab": "home",
            "success": request.query_params.get("success"),
            "error": request.query_params.get("error"),
            "pay_recipient": request.query_params.get("pay"),
            **ctx,
        },
    )


@app.get("/payments", response_class=HTMLResponse)
def payments_page(request: Request, db: DbSession):
    """Полная история операций с поиском."""
    user = get_current_user(request, db)
    if user is None:
        return RedirectResponse(url="/", status_code=status.HTTP_303_SEE_OTHER)
    if user.role == "admin":
        return RedirectResponse(url="/admin", status_code=status.HTTP_303_SEE_OTHER)

    ctx = get_context_users(db, user.id)
    txs = user_transactions(db, user.id)

    return templates.TemplateResponse(
        request,
        "payments.html",
        {
            "request": request,
            "user": user,
            "transactions": txs,
            "active_tab": "payments",
            "success": request.query_params.get("success"),
            "error": request.query_params.get("error"),
            **ctx,
        },
    )


@app.get("/qr", response_class=HTMLResponse)
def qr_page(request: Request, db: DbSession):
    """QR-код для приёма платежей и оплата по ссылке."""
    user = get_current_user(request, db)
    if user is None:
        return RedirectResponse(url="/", status_code=status.HTTP_303_SEE_OTHER)
    if user.role == "admin":
        return RedirectResponse(url="/admin", status_code=status.HTTP_303_SEE_OTHER)

    ctx = get_context_users(db, user.id)
    pay_link = f"dvorpay://pay/{user.id}"

    return templates.TemplateResponse(
        request,
        "qr.html",
        {
            "request": request,
            "user": user,
            "pay_link": pay_link,
            "active_tab": "qr",
            **ctx,
        },
    )


@app.get("/contacts", response_class=HTMLResponse)
def contacts_page(request: Request, db: DbSession):
    """Список жителей и организаций для перевода."""
    user = get_current_user(request, db)
    if user is None:
        return RedirectResponse(url="/", status_code=status.HTTP_303_SEE_OTHER)
    if user.role == "admin":
        return RedirectResponse(url="/admin", status_code=status.HTTP_303_SEE_OTHER)

    ctx = get_context_users(db, user.id)

    return templates.TemplateResponse(
        request,
        "contacts.html",
        {
            "request": request,
            "user": user,
            "active_tab": "contacts",
            **ctx,
        },
    )


@app.get("/admin", response_class=HTMLResponse)
def admin_page(request: Request, db: DbSession):
    """Админ-панель: начисление дублей и обзор пользователей."""
    user = get_current_user(request, db)
    if user is None:
        return RedirectResponse(url="/", status_code=status.HTTP_303_SEE_OTHER)
    if user.role != "admin":
        return RedirectResponse(url="/dashboard", status_code=status.HTTP_303_SEE_OTHER)

    ctx = get_context_users(db, user.id)
    all_txs = db.query(TransactionORM).order_by(TransactionORM.created_at.desc()).limit(20).all()
    nfc_cards = db.query(NFCCardORM).order_by(NFCCardORM.owner_id).all()
    geofence = geofence_to_dict(get_geofence(db))

    return templates.TemplateResponse(
        request,
        "admin.html",
        {
            "request": request,
            "user": user,
            "transactions": all_txs,
            "nfc_cards": nfc_cards,
            "geofence": geofence,
            "active_tab": "admin",
            "success": request.query_params.get("success"),
            "error": request.query_params.get("error"),
            "issued_url": request.query_params.get("issued_url"),
            **ctx,
        },
    )


@app.post("/admin/credit")
def admin_credit(
    request: Request,
    db: DbSession,
    user_id: str = Form(...),
    amount: float = Form(...),
    comment: str = Form(""),
):
    """Начисление дублей пользователю (только admin)."""
    admin = get_current_user(request, db)
    if admin is None:
        return RedirectResponse(url="/", status_code=status.HTTP_303_SEE_OTHER)
    if admin.role != "admin":
        return RedirectResponse(url="/dashboard", status_code=status.HTTP_303_SEE_OTHER)

    target_id = user_id.strip()
    if amount <= 0:
        return RedirectResponse(
            url="/admin?error=Сумма+должна+быть+больше+нуля",
            status_code=status.HTTP_303_SEE_OTHER,
        )

    target = db.query(UserORM).filter(UserORM.id == target_id).first()
    if target is None:
        return RedirectResponse(
            url="/admin?error=Пользователь+не+найден",
            status_code=status.HTTP_303_SEE_OTHER,
        )

    note = comment.strip() or "Начисление администрацией"
    target.balance += amount

    tx = TransactionORM(
        sender_id=admin.id,
        recipient_id=target.id,
        amount=amount,
        comment=note,
    )
    db.add(tx)
    db.commit()

    return RedirectResponse(
        url=f"/admin?success=Начислено+{amount:.2f}+дублей+пользователю+{target_id}",
        status_code=status.HTTP_303_SEE_OTHER,
    )


@app.post("/admin/users/create")
def admin_create_user(
    request: Request,
    db: DbSession,
    user_id: str = Form(...),
    name: str = Form(...),
    password: str = Form(...),
    role: str = Form(...),
    balance: float = Form(0.0),
):
    """Создание нового пользователя (только admin). Открытой регистрации нет."""
    admin = get_current_user(request, db)
    if admin is None:
        return RedirectResponse(url="/", status_code=status.HTTP_303_SEE_OTHER)
    if admin.role != "admin":
        return RedirectResponse(url="/dashboard", status_code=status.HTTP_303_SEE_OTHER)

    login = user_id.strip().lower()
    if not login or not login.replace("_", "").isalnum():
        return RedirectResponse(
            url="/admin?error=Логин+должен+содержать+только+буквы,+цифры+и+_",
            status_code=status.HTTP_303_SEE_OTHER,
        )

    if role not in ("user", "business", "admin"):
        return RedirectResponse(
            url="/admin?error=Недопустимая+роль",
            status_code=status.HTTP_303_SEE_OTHER,
        )

    if balance < 0:
        return RedirectResponse(
            url="/admin?error=Баланс+не+может+быть+отрицательным",
            status_code=status.HTTP_303_SEE_OTHER,
        )

    if db.query(UserORM).filter(UserORM.id == login).first():
        return RedirectResponse(
            url="/admin?error=Пользователь+с+таким+логином+уже+существует",
            status_code=status.HTTP_303_SEE_OTHER,
        )

    db.add(
        UserORM(
            id=login,
            name=name.strip(),
            password=password,
            balance=balance,
            role=role,
        )
    )
    db.commit()

    return RedirectResponse(
        url=f"/admin?success=Создан+пользователь+{login}",
        status_code=status.HTTP_303_SEE_OTHER,
    )


@app.post("/admin/nfc/issue")
def admin_issue_nfc(
    request: Request,
    db: DbSession,
    owner_id: str = Form(...),
    pin: str = Form(...),
):
    """Выпуск новой NFC-карты для жителя (только admin)."""
    admin = get_current_user(request, db)
    if admin is None:
        return RedirectResponse(url="/", status_code=status.HTTP_303_SEE_OTHER)
    if admin.role != "admin":
        return RedirectResponse(url="/dashboard", status_code=status.HTTP_303_SEE_OTHER)

    owner = owner_id.strip()
    pin_code = pin.strip()

    if not pin_code.isdigit() or len(pin_code) != 4:
        return RedirectResponse(
            url="/admin?error=ПИН-код+карты+должен+состоять+из+4+цифр",
            status_code=status.HTTP_303_SEE_OTHER,
        )

    owner_user = db.query(UserORM).filter(UserORM.id == owner).first()
    if owner_user is None:
        return RedirectResponse(
            url="/admin?error=Владелец+карты+не+найден",
            status_code=status.HTTP_303_SEE_OTHER,
        )

    card_token = str(uuid.uuid4())
    db.add(
        NFCCardORM(
            card_token=card_token,
            owner_id=owner,
            pin=pin_code,
            failed_attempts=0,
            is_blocked=False,
        )
    )
    db.commit()

    pay_url = f"/pay?card_token={card_token}"
    return RedirectResponse(
        url=f"/admin?success=NFC-карта+выпущена+для+{owner}&issued_url={quote(pay_url, safe='')}",
        status_code=status.HTTP_303_SEE_OTHER,
    )


@app.post("/admin/nfc/unblock")
def admin_unblock_nfc(
    request: Request,
    db: DbSession,
    card_token: str = Form(...),
):
    """Разблокировка NFC-карты и сброс счётчика ошибок."""
    admin = get_current_user(request, db)
    if admin is None or admin.role != "admin":
        return RedirectResponse(url="/", status_code=status.HTTP_303_SEE_OTHER)

    card = db.query(NFCCardORM).filter(NFCCardORM.card_token == card_token.strip()).first()
    if card is None:
        return RedirectResponse(
            url="/admin?error=Карта+не+найдена",
            status_code=status.HTTP_303_SEE_OTHER,
        )

    card.is_blocked = False
    card.failed_attempts = 0
    db.commit()

    return RedirectResponse(
        url="/admin?success=Карта+разблокирована",
        status_code=status.HTTP_303_SEE_OTHER,
    )


@app.post("/admin/geofence/save")
def admin_save_geofence(
    request: Request,
    db: DbSession,
    mode: str = Form(...),
    center_lat: float = Form(...),
    center_lon: float = Form(...),
    radius_meters: float = Form(...),
    polygon_json: str = Form("[]"),
):
    """Сохранение зоны NFC-оплаты (круг или нарисованный полигон)."""
    admin = get_current_user(request, db)
    if admin is None or admin.role != "admin":
        return RedirectResponse(url="/", status_code=status.HTTP_303_SEE_OTHER)

    if mode not in ("circle", "polygon"):
        return RedirectResponse(
            url="/admin?error=Недопустимый+режим+геозоны",
            status_code=status.HTTP_303_SEE_OTHER,
        )

    try:
        polygon = json.loads(polygon_json or "[]")
    except json.JSONDecodeError:
        return RedirectResponse(
            url="/admin?error=Некорректный+формат+полигона",
            status_code=status.HTTP_303_SEE_OTHER,
        )

    if mode == "polygon":
        if len(polygon) < 3:
            return RedirectResponse(
                url="/admin?error=Полигон+должен+иметь+минимум+3+точки",
                status_code=status.HTTP_303_SEE_OTHER,
            )
    elif radius_meters <= 0:
        return RedirectResponse(
            url="/admin?error=Радиус+должен+быть+больше+нуля",
            status_code=status.HTTP_303_SEE_OTHER,
        )

    gf = get_geofence(db)
    gf.mode = mode
    gf.center_lat = center_lat
    gf.center_lon = center_lon
    gf.radius_meters = radius_meters
    gf.polygon_json = json.dumps(polygon)
    db.commit()

    return RedirectResponse(
        url="/admin?success=Территория+оплаты+сохранена",
        status_code=status.HTTP_303_SEE_OTHER,
    )


# ---------------------------------------------------------------------------
# NFC-ОПЛАТА (изолированный модуль терминала)
# ---------------------------------------------------------------------------


@app.get("/pay", response_class=HTMLResponse)
def nfc_scan_entry(request: Request, card_token: str, db: DbSession):
    """
    Точка входа при сканировании NFC-карты.
    Создаёт одноразовую сессию и перенаправляет business/admin на терминал.
    """
    scanner = get_current_user(request, db)
    if scanner is None:
        return RedirectResponse(
            url=f"/?error=Войдите+как+продавец+перед+сканированием+карты",
            status_code=status.HTTP_303_SEE_OTHER,
        )

    card = db.query(NFCCardORM).filter(NFCCardORM.card_token == card_token.strip()).first()
    if card is None:
        return templates.TemplateResponse(
            request,
            "pay.html",
            pay_template_context(request, error="NFC-карта не найдена в системе.", merchant=scanner),
        )

    if card.is_blocked:
        return templates.TemplateResponse(
            request,
            "pay.html",
            pay_template_context(request, error="Карта заблокирована!", merchant=scanner),
        )

    if scanner.role == "user":
        return templates.TemplateResponse(
            request,
            "pay.html",
            pay_template_context(
                request,
                error="Доступ запрещен. Вы не являетесь бизнес-аккаунтом!",
                merchant=scanner,
            ),
        )

    if scanner.role not in ("business", "admin"):
        return templates.TemplateResponse(
            request,
            "pay.html",
            pay_template_context(
                request,
                error="Доступ запрещен. Вы не являетесь бизнес-аккаунтом!",
                merchant=scanner,
            ),
        )

    session_token = str(uuid.uuid4())
    db.add(
        DynamicSessionORM(
            session_token=session_token,
            card_token=card.card_token,
            expires_at=utcnow() + timedelta(minutes=NFC_SESSION_TTL_MINUTES),
            is_used=False,
        )
    )
    db.commit()

    return RedirectResponse(
        url=f"/pay/terminal?session={session_token}",
        status_code=status.HTTP_303_SEE_OTHER,
    )


@app.get("/pay/terminal", response_class=HTMLResponse)
def nfc_pay_terminal(request: Request, session: str, db: DbSession):
    """Защищённая страница терминала оплаты по одноразовой сессии."""
    merchant = get_current_user(request, db)
    if merchant is None:
        return RedirectResponse(url="/", status_code=status.HTTP_303_SEE_OTHER)

    if merchant.role not in ("business", "admin"):
        return templates.TemplateResponse(
            request,
            "pay.html",
            pay_template_context(
                request,
                error="Доступ запрещен. Вы не являетесь бизнес-аккаунтом!",
                merchant=merchant,
            ),
        )

    dyn = db.query(DynamicSessionORM).filter(DynamicSessionORM.session_token == session).first()
    if dyn is None:
        return templates.TemplateResponse(
            request,
            "pay.html",
            pay_template_context(
                request,
                error="Срок действия сессии оплаты истек!",
                merchant=merchant,
            ),
        )

    expires = dyn.expires_at
    if expires.tzinfo is None:
        expires = expires.replace(tzinfo=timezone.utc)

    if dyn.is_used or utcnow() > expires:
        return templates.TemplateResponse(
            request,
            "pay.html",
            pay_template_context(
                request,
                error="Срок действия сессии оплаты истек!",
                merchant=merchant,
            ),
        )

    card = db.query(NFCCardORM).filter(NFCCardORM.card_token == dyn.card_token).first()
    if card is None or card.is_blocked:
        return templates.TemplateResponse(
            request,
            "pay.html",
            pay_template_context(request, error="Карта заблокирована!", merchant=merchant),
        )

    owner = db.query(UserORM).filter(UserORM.id == card.owner_id).first()
    buyer_name = owner.name if owner else card.owner_id

    return templates.TemplateResponse(
        request,
        "pay.html",
        pay_template_context(
            request,
            terminal_mode=True,
            buyer_name=buyer_name,
            session_token=session,
            merchant=merchant,
            success=request.query_params.get("success"),
            error=request.query_params.get("error"),
        ),
    )


@app.post("/pay/execute")
def nfc_pay_execute(
    request: Request,
    db: DbSession,
    session_token: str = Form(...),
    amount: float = Form(...),
    comment: str = Form(""),
    pin: str = Form(...),
    latitude: float = Form(...),
    longitude: float = Form(...),
):
    """Проведение NFC-оплаты с полной проверкой безопасности."""
    merchant = get_current_user(request, db)
    if merchant is None:
        return RedirectResponse(url="/", status_code=status.HTTP_303_SEE_OTHER)

    if merchant.role not in ("business", "admin"):
        return RedirectResponse(
            url=f"/pay/terminal?session={session_token}&error={quote('Доступ запрещен')}",
            status_code=status.HTTP_303_SEE_OTHER,
        )

    dyn = (
        db.query(DynamicSessionORM)
        .filter(DynamicSessionORM.session_token == session_token.strip())
        .first()
    )
    if dyn is None:
        return RedirectResponse(
            url=f"/pay/terminal?session={session_token}&error={quote('Срок действия сессии оплаты истек!')}",
            status_code=status.HTTP_303_SEE_OTHER,
        )

    expires = dyn.expires_at
    if expires.tzinfo is None:
        expires = expires.replace(tzinfo=timezone.utc)

    if dyn.is_used or utcnow() > expires:
        return RedirectResponse(
            url=f"/pay/terminal?session={session_token}&error={quote('Срок действия сессии оплаты истек!')}",
            status_code=status.HTTP_303_SEE_OTHER,
        )

    # Replay-защита: помечаем сессию использованной сразу после валидации срока
    dyn.is_used = True
    db.commit()

    def merchant_redirect(error_msg: str | None = None, success_msg: str | None = None) -> RedirectResponse:
        base = "/payments" if merchant.role == "business" else "/admin"
        if success_msg:
            return RedirectResponse(
                url=f"{base}?success={quote(success_msg)}",
                status_code=status.HTTP_303_SEE_OTHER,
            )
        return RedirectResponse(
            url=f"{base}?error={quote(error_msg or 'Ошибка оплаты')}",
            status_code=status.HTTP_303_SEE_OTHER,
        )

    card = db.query(NFCCardORM).filter(NFCCardORM.card_token == dyn.card_token).first()
    if card is None:
        return merchant_redirect("Карта не найдена")

    if card.is_blocked:
        return merchant_redirect("Карта заблокирована!")

    if not is_inside_dvor(latitude, longitude, db):
        return merchant_redirect(
            "Ошибка геопозиции. Платёж должен совершаться на территории Двора!"
        )

    if amount <= 0:
        return merchant_redirect("Сумма должна быть больше нуля")

    pin_code = pin.strip()
    if pin_code != card.pin:
        card.failed_attempts += 1
        if card.failed_attempts >= NFC_MAX_PIN_ATTEMPTS:
            card.is_blocked = True
            db.commit()
            return merchant_redirect("Карта заблокирована за 3 неверных ввода ПИН-кода!")
        db.commit()
        left = NFC_MAX_PIN_ATTEMPTS - card.failed_attempts
        return merchant_redirect(
            f"Неверный ПИН-код. Осталось попыток: {left}. Приложите карту снова."
        )

    card.failed_attempts = 0

    buyer = db.query(UserORM).filter(UserORM.id == card.owner_id).first()
    if buyer is None:
        return merchant_redirect("Владелец карты не найден")

    note = comment.strip() or f"NFC-оплата у {merchant.name}"
    try:
        update_balance(db, buyer.id, merchant.id, amount, note)
    except ValueError as exc:
        db.rollback()
        dyn.is_used = True
        db.commit()
        return merchant_redirect(str(exc))

    db.commit()

    return merchant_redirect(
        success_msg=f"Оплата принята: {amount:.2f} дублей от {buyer.name}",
    )


@app.post("/transfer")
def transfer(
    request: Request,
    db: DbSession,
    recipient: str = Form(...),
    amount: float = Form(...),
    comment: str = Form(""),
    pin: str = Form(""),
    commercial: str = Form(""),
):
    """
    Перевод дублей другому пользователю.

    Правила:
    - сумма > 0, достаточно средств, нельзя переводить себе;
    - коммерческий платёж возможен только на аккаунт business;
    - обычные пользователи (user) не могут принимать коммерческие платежи;
    - при переводе на business обязателен правильный ПИН отправителя.
    """
    sender = get_current_user(request, db)
    if sender is None:
        return RedirectResponse(url="/", status_code=status.HTTP_303_SEE_OTHER)

    recipient_id = recipient.strip()
    is_commercial = commercial == "on"

    # --- базовые проверки ---
    if amount <= 0:
        return RedirectResponse(
            url="/dashboard?error=Сумма+должна+быть+больше+нуля",
            status_code=status.HTTP_303_SEE_OTHER,
        )

    if recipient_id == sender.id:
        return RedirectResponse(
            url="/dashboard?error=Нельзя+переводить+самому+себе",
            status_code=status.HTTP_303_SEE_OTHER,
        )

    recipient_user = db.query(UserORM).filter(UserORM.id == recipient_id).first()
    if recipient_user is None:
        return RedirectResponse(
            url="/dashboard?error=Получатель+не+найден",
            status_code=status.HTTP_303_SEE_OTHER,
        )

    if sender.balance < amount:
        return RedirectResponse(
            url="/dashboard?error=Недостаточно+дублей+на+балансе",
            status_code=status.HTTP_303_SEE_OTHER,
        )

    # --- бизнес-валидация ---
    if is_commercial and recipient_user.role == "user":
        return RedirectResponse(
            url="/dashboard?error=Обычные+пользователи+не+могут+принимать+коммерческие+платежи",
            status_code=status.HTTP_303_SEE_OTHER,
        )

    if is_commercial and recipient_user.role != "business":
        return RedirectResponse(
            url="/dashboard?error=Коммерческие+платежи+доступны+только+для+организаций",
            status_code=status.HTTP_303_SEE_OTHER,
        )

    # Перевод на организацию (business) всегда требует ПИН, даже без галочки «коммерческий»
    needs_pin = recipient_user.role == "business" or is_commercial
    if needs_pin:
        if not pin or pin != sender.password:
            return RedirectResponse(
                url="/dashboard?error=Для+оплаты+организации+введите+правильный+ПИН-код",
                status_code=status.HTTP_303_SEE_OTHER,
            )

    # --- проведение перевода ---
    sender.balance -= amount
    recipient_user.balance += amount

    tx = TransactionORM(
        sender_id=sender.id,
        recipient_id=recipient_user.id,
        amount=amount,
        comment=comment.strip(),
    )
    db.add(tx)
    db.commit()

    return RedirectResponse(
        url="/dashboard?success=Перевод+успешно+выполнен",
        status_code=status.HTTP_303_SEE_OTHER,
    )
