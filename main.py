import os
import uuid

from fastapi import Depends, FastAPI, Header, HTTPException
from sqlalchemy.orm import Session

from database import Base, engine, get_db, now_utc
from models import AccessRule, BusinessElement, Role, User, UserSession
from schemas import (
    CurrentAuth,
    ElementIn,
    ElementOut,
    ElementPatch,
    LoginIn,
    MockIn,
    ProfileUpdateIn,
    RegisterIn,
    RoleIn,
    RoleOut,
    RolePatch,
    RuleIn,
    RuleOut,
    RulePatch,
    TokenOut,
    UserOut,
)
from security import create_access_token, decode_access_token, hash_password, verify_password
from mock_store import create_item, delete_item, get_item, list_items, update_item

APP_NAME = os.getenv("APP_NAME", "Effective Mobile Test API")

app = FastAPI(title=APP_NAME)


@app.on_event("startup")
def on_startup() -> None:
    Base.metadata.create_all(bind=engine)


@app.get("/health")
def health() -> dict:
    return {"status": "ok"}


def user_to_out(user: User) -> UserOut:
    return UserOut(
        id=user.id,
        first_name=user.first_name,
        last_name=user.last_name,
        email=user.email,
        role=user.role.name if user.role else "",
        is_active=user.is_active,
        created_at=user.created_at,
    )


def rule_to_out(rule: AccessRule) -> RuleOut:
    return RuleOut(
        id=rule.id,
        role_id=rule.role_id,
        role_name=rule.role.name if rule.role else "",
        element_id=rule.element_id,
        element_code=rule.element.code if rule.element else "",
        read_permission=rule.read_permission,
        read_all_permission=rule.read_all_permission,
        create_permission=rule.create_permission,
        update_permission=rule.update_permission,
        update_all_permission=rule.update_all_permission,
        delete_permission=rule.delete_permission,
        delete_all_permission=rule.delete_all_permission,
        created_at=rule.created_at,
        updated_at=rule.updated_at,
    )


def get_current_auth(
    authorization: str | None = Header(default=None),
    db: Session = Depends(get_db),
) -> CurrentAuth:
    if not authorization:
        raise HTTPException(status_code=401, detail="Необходима авторизация")

    parts = authorization.split()
    if len(parts) != 2 or parts[0].lower() != "bearer":
        raise HTTPException(status_code=401, detail="Неверный Authorization header")

    token = parts[1]
    try:
        payload = decode_access_token(token)
    except Exception:
        raise HTTPException(status_code=401, detail="Токен недействителен")

    user_id = payload.get("sub")
    jti = payload.get("jti")
    if not user_id or not jti:
        raise HTTPException(status_code=401, detail="В токене не хватает данных")

    user = db.query(User).filter(User.id == int(user_id), User.is_active.is_(True)).first()
    if not user:
        raise HTTPException(status_code=401, detail="Пользователь не найден")

    session = (
        db.query(UserSession)
        .filter(
            UserSession.user_id == user.id,
            UserSession.jti == jti,
            UserSession.revoked_at.is_(None),
        )
        .first()
    )
    if not session:
        raise HTTPException(status_code=401, detail="Сессия не найдена или отозвана")

    if session.expires_at <= now_utc():
        raise HTTPException(status_code=401, detail="Сессия истекла")

    return CurrentAuth(user_id=user.id, jti=jti)


def get_current_user(
    auth: CurrentAuth = Depends(get_current_auth),
    db: Session = Depends(get_db),
) -> User:
    user = db.query(User).join(Role, User.role_id == Role.id).filter(User.id == auth.user_id).first()
    if not user:
        raise HTTPException(status_code=401, detail="Пользователь не найден")
    return user


def require_admin(user: User = Depends(get_current_user)) -> User:
    if not user.role or user.role.name != "admin":
        raise HTTPException(status_code=403, detail="Доступно только администратору")
    return user


def get_access_rule(db: Session, role_id: int, element_code: str) -> AccessRule | None:
    return (
        db.query(AccessRule)
        .join(BusinessElement, AccessRule.element_id == BusinessElement.id)
        .filter(AccessRule.role_id == role_id, BusinessElement.code == element_code)
        .first()
    )


def get_read_scope(db: Session, user: User, element_code: str) -> str:
    rule = get_access_rule(db, user.role_id, element_code)
    if not rule:
        return "none"
    if rule.read_all_permission:
        return "all"
    if rule.read_permission:
        return "own"
    return "none"


def has_access(db: Session, user: User, element_code: str, action: str, owner_id: int | None = None) -> bool:
    rule = get_access_rule(db, user.role_id, element_code)
    if not rule:
        return False

    if action == "create":
        return bool(rule.create_permission)

    all_flag = getattr(rule, f"{action}_all_permission")
    own_flag = getattr(rule, f"{action}_permission")

    if all_flag:
        return True
    if not own_flag:
        return False

    if owner_id is None:
        return True
    return int(owner_id) == int(user.id)


@app.post("/auth/register", response_model=UserOut, status_code=201)
def register(payload: RegisterIn, db: Session = Depends(get_db)):
    if payload.password != payload.password_repeat:
        raise HTTPException(status_code=400, detail="Пароли не совпадают")

    email = payload.email.lower()
    exists = db.query(User).filter(User.email == email).first()
    if exists:
        raise HTTPException(status_code=400, detail="Пользователь с таким email уже существует")

    user_role = db.query(Role).filter(Role.name == "user").first()
    if not user_role:
        raise HTTPException(status_code=400, detail="Нет роли user. Сначала выполни: python seed.py")

    user = User(
        role_id=user_role.id,
        first_name=payload.first_name,
        last_name=payload.last_name,
        email=email,
        password_hash=hash_password(payload.password),
        is_active=True,
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    return user_to_out(user)


@app.post("/auth/login", response_model=TokenOut)
def login(payload: LoginIn, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.email == payload.email.lower()).first()
    if not user or not verify_password(payload.password, user.password_hash):
        raise HTTPException(status_code=400, detail="Неверный email или пароль")
    if not user.is_active:
        raise HTTPException(status_code=400, detail="Пользователь деактивирован")

    jti = str(uuid.uuid4())
    token, expires_at = create_access_token(user.id, jti)

    session = UserSession(user_id=user.id, jti=jti, expires_at=expires_at)
    db.add(session)
    db.commit()

    return TokenOut(token_type="Bearer", access_token=token, expires_at=expires_at, user=user_to_out(user))


@app.post("/auth/logout", status_code=204)
def logout(auth: CurrentAuth = Depends(get_current_auth), db: Session = Depends(get_db)):
    session = (
        db.query(UserSession)
        .filter(
            UserSession.user_id == auth.user_id,
            UserSession.jti == auth.jti,
            UserSession.revoked_at.is_(None),
        )
        .first()
    )
    if session:
        session.revoked_at = now_utc()
        db.add(session)
        db.commit()
    return None


@app.get("/auth/me", response_model=UserOut)
def me(user: User = Depends(get_current_user)):
    return user_to_out(user)


@app.patch("/auth/me", response_model=UserOut)
def me_update(
    payload: ProfileUpdateIn,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    data = payload.model_dump(exclude_unset=True)
    if "first_name" in data:
        user.first_name = data["first_name"]
    if "last_name" in data:
        user.last_name = data["last_name"]
    if "password" in data and data["password"]:
        user.password_hash = hash_password(data["password"])

    db.add(user)
    db.commit()
    db.refresh(user)
    return user_to_out(user)


@app.delete("/auth/me", status_code=204)
def me_delete(user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    user.is_active = False
    db.add(user)

    db.query(UserSession).filter(
        UserSession.user_id == user.id,
        UserSession.revoked_at.is_(None),
    ).update({UserSession.revoked_at: now_utc()})

    db.commit()
    return None


@app.get("/admin/roles", response_model=list[RoleOut])
def roles_list(_admin: User = Depends(require_admin), db: Session = Depends(get_db)):
    return db.query(Role).order_by(Role.id).all()


@app.post("/admin/roles", response_model=RoleOut, status_code=201)
def roles_create(payload: RoleIn, _admin: User = Depends(require_admin), db: Session = Depends(get_db)):
    if db.query(Role).filter(Role.name == payload.name).first():
        raise HTTPException(status_code=400, detail="Роль уже существует")
    role = Role(name=payload.name, description=payload.description)
    db.add(role)
    db.commit()
    db.refresh(role)
    return role


@app.get("/admin/roles/{role_id}", response_model=RoleOut)
def roles_get(role_id: int, _admin: User = Depends(require_admin), db: Session = Depends(get_db)):
    role = db.query(Role).filter(Role.id == role_id).first()
    if not role:
        raise HTTPException(status_code=404, detail="Роль не найдена")
    return role


@app.patch("/admin/roles/{role_id}", response_model=RoleOut)
def roles_patch(
    role_id: int,
    payload: RolePatch,
    _admin: User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    role = db.query(Role).filter(Role.id == role_id).first()
    if not role:
        raise HTTPException(status_code=404, detail="Роль не найдена")

    for field, value in payload.model_dump(exclude_unset=True).items():
        setattr(role, field, value)

    db.add(role)
    db.commit()
    db.refresh(role)
    return role


@app.delete("/admin/roles/{role_id}", status_code=204)
def roles_delete(role_id: int, _admin: User = Depends(require_admin), db: Session = Depends(get_db)):
    role = db.query(Role).filter(Role.id == role_id).first()
    if not role:
        raise HTTPException(status_code=404, detail="Роль не найдена")

    db.delete(role)
    try:
        db.commit()
    except Exception:
        db.rollback()
        raise HTTPException(status_code=400, detail="Нельзя удалить роль, пока она используется")
    return None


@app.get("/admin/elements", response_model=list[ElementOut])
def elements_list(_admin: User = Depends(require_admin), db: Session = Depends(get_db)):
    return db.query(BusinessElement).order_by(BusinessElement.id).all()


@app.post("/admin/elements", response_model=ElementOut, status_code=201)
def elements_create(payload: ElementIn, _admin: User = Depends(require_admin), db: Session = Depends(get_db)):
    if db.query(BusinessElement).filter(BusinessElement.code == payload.code).first():
        raise HTTPException(status_code=400, detail="Элемент с таким code уже существует")
    element = BusinessElement(code=payload.code, title=payload.title)
    db.add(element)
    db.commit()
    db.refresh(element)
    return element


@app.get("/admin/elements/{element_id}", response_model=ElementOut)
def elements_get(element_id: int, _admin: User = Depends(require_admin), db: Session = Depends(get_db)):
    element = db.query(BusinessElement).filter(BusinessElement.id == element_id).first()
    if not element:
        raise HTTPException(status_code=404, detail="Элемент не найден")
    return element


@app.patch("/admin/elements/{element_id}", response_model=ElementOut)
def elements_patch(
    element_id: int,
    payload: ElementPatch,
    _admin: User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    element = db.query(BusinessElement).filter(BusinessElement.id == element_id).first()
    if not element:
        raise HTTPException(status_code=404, detail="Элемент не найден")

    for field, value in payload.model_dump(exclude_unset=True).items():
        setattr(element, field, value)

    db.add(element)
    db.commit()
    db.refresh(element)
    return element


@app.delete("/admin/elements/{element_id}", status_code=204)
def elements_delete(element_id: int, _admin: User = Depends(require_admin), db: Session = Depends(get_db)):
    element = db.query(BusinessElement).filter(BusinessElement.id == element_id).first()
    if not element:
        raise HTTPException(status_code=404, detail="Элемент не найден")

    db.delete(element)
    try:
        db.commit()
    except Exception:
        db.rollback()
        raise HTTPException(status_code=400, detail="Нельзя удалить элемент, пока он используется")
    return None


@app.get("/admin/rules", response_model=list[RuleOut])
def rules_list(_admin: User = Depends(require_admin), db: Session = Depends(get_db)):
    rules = db.query(AccessRule).order_by(AccessRule.id).all()
    return [rule_to_out(rule) for rule in rules]


@app.post("/admin/rules", response_model=RuleOut, status_code=201)
def rules_create(payload: RuleIn, _admin: User = Depends(require_admin), db: Session = Depends(get_db)):
    role = db.query(Role).filter(Role.id == payload.role_id).first()
    element = db.query(BusinessElement).filter(BusinessElement.id == payload.element_id).first()
    if not role or not element:
        raise HTTPException(status_code=400, detail="Неверный role_id или element_id")

    exists = (
        db.query(AccessRule)
        .filter(AccessRule.role_id == payload.role_id, AccessRule.element_id == payload.element_id)
        .first()
    )
    if exists:
        raise HTTPException(status_code=400, detail="Правило для этой пары уже существует")

    rule = AccessRule(**payload.model_dump())
    db.add(rule)
    db.commit()
    db.refresh(rule)
    return rule_to_out(rule)


@app.get("/admin/rules/{rule_id}", response_model=RuleOut)
def rules_get(rule_id: int, _admin: User = Depends(require_admin), db: Session = Depends(get_db)):
    rule = db.query(AccessRule).filter(AccessRule.id == rule_id).first()
    if not rule:
        raise HTTPException(status_code=404, detail="Правило не найдено")
    return rule_to_out(rule)


@app.patch("/admin/rules/{rule_id}", response_model=RuleOut)
def rules_patch(
    rule_id: int,
    payload: RulePatch,
    _admin: User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    rule = db.query(AccessRule).filter(AccessRule.id == rule_id).first()
    if not rule:
        raise HTTPException(status_code=404, detail="Правило не найдено")

    data = payload.model_dump(exclude_unset=True)
    if "role_id" in data and not db.query(Role).filter(Role.id == data["role_id"]).first():
        raise HTTPException(status_code=400, detail="Неверный role_id")
    if "element_id" in data and not db.query(BusinessElement).filter(BusinessElement.id == data["element_id"]).first():
        raise HTTPException(status_code=400, detail="Неверный element_id")

    for field, value in data.items():
        setattr(rule, field, value)

    db.add(rule)
    try:
        db.commit()
    except Exception:
        db.rollback()
        raise HTTPException(status_code=400, detail="Ошибка обновления правила")
    db.refresh(rule)
    return rule_to_out(rule)


@app.delete("/admin/rules/{rule_id}", status_code=204)
def rules_delete(rule_id: int, _admin: User = Depends(require_admin), db: Session = Depends(get_db)):
    rule = db.query(AccessRule).filter(AccessRule.id == rule_id).first()
    if not rule:
        raise HTTPException(status_code=404, detail="Правило не найдено")
    db.delete(rule)
    db.commit()
    return None


def mock_list_api(resource: str, user: User, db: Session):
    scope = get_read_scope(db, user, resource)
    if scope == "none":
        raise HTTPException(status_code=403, detail="Нет прав на чтение этого ресурса")
    items = list_items(resource)
    if scope == "own":
        items = [item for item in items if item["owner_id"] == user.id]
    return items


def mock_get_api(resource: str, item_id: int, user: User, db: Session):
    item = get_item(resource, item_id)
    if not item:
        raise HTTPException(status_code=404, detail="Объект не найден")
    if not has_access(db, user, resource, "read", owner_id=item["owner_id"]):
        raise HTTPException(status_code=403, detail="Нет прав на чтение этого объекта")
    return item


def mock_create_api(resource: str, payload: MockIn, user: User, db: Session):
    if not has_access(db, user, resource, "create"):
        raise HTTPException(status_code=403, detail="Нет прав на создание этого ресурса")
    return create_item(resource, payload.name, user.id, payload.description)


def mock_patch_api(resource: str, item_id: int, payload: MockIn, user: User, db: Session):
    item = get_item(resource, item_id)
    if not item:
        raise HTTPException(status_code=404, detail="Объект не найден")
    if not has_access(db, user, resource, "update", owner_id=item["owner_id"]):
        raise HTTPException(status_code=403, detail="Нет прав на изменение этого объекта")
    updated = update_item(resource, item_id, payload.name, payload.description)
    if not updated:
        raise HTTPException(status_code=404, detail="Объект не найден")
    return updated


def mock_delete_api(resource: str, item_id: int, user: User, db: Session):
    item = get_item(resource, item_id)
    if not item:
        raise HTTPException(status_code=404, detail="Объект не найден")
    if not has_access(db, user, resource, "delete", owner_id=item["owner_id"]):
        raise HTTPException(status_code=403, detail="Нет прав на удаление этого объекта")
    deleted = delete_item(resource, item_id)
    if not deleted:
        raise HTTPException(status_code=404, detail="Объект не найден")


@app.get("/mock/products")
def products_list(user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    return mock_list_api("products", user, db)


@app.post("/mock/products", status_code=201)
def products_create(payload: MockIn, user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    return mock_create_api("products", payload, user, db)


@app.get("/mock/products/{item_id}")
def products_get(item_id: int, user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    return mock_get_api("products", item_id, user, db)


@app.patch("/mock/products/{item_id}")
def products_patch(
    item_id: int,
    payload: MockIn,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    return mock_patch_api("products", item_id, payload, user, db)


@app.delete("/mock/products/{item_id}", status_code=204)
def products_delete(item_id: int, user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    mock_delete_api("products", item_id, user, db)
    return None


@app.get("/mock/orders")
def orders_list(user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    return mock_list_api("orders", user, db)


@app.post("/mock/orders", status_code=201)
def orders_create(payload: MockIn, user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    return mock_create_api("orders", payload, user, db)


@app.get("/mock/orders/{item_id}")
def orders_get(item_id: int, user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    return mock_get_api("orders", item_id, user, db)


@app.patch("/mock/orders/{item_id}")
def orders_patch(
    item_id: int,
    payload: MockIn,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    return mock_patch_api("orders", item_id, payload, user, db)


@app.delete("/mock/orders/{item_id}", status_code=204)
def orders_delete(item_id: int, user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    mock_delete_api("orders", item_id, user, db)
    return None
