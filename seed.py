import time

from sqlalchemy import text
from sqlalchemy.exc import OperationalError
from sqlalchemy.orm import Session

from database import Base, SessionLocal, engine
from models import AccessRule, BusinessElement, Role, User
from security import hash_password


def wait_for_db(max_attempts: int = 30, sleep_sec: int = 2) -> None:
    for attempt in range(1, max_attempts + 1):
        try:
            with engine.connect() as conn:
                conn.execute(text("SELECT 1"))
            return
        except OperationalError:
            if attempt == max_attempts:
                raise
            time.sleep(sleep_sec)


def seed_demo_data(db: Session) -> None:
    roles_data = {
        "admin": "Полный доступ к системе",
        "manager": "Управление заказами и товарами",
        "user": "Базовый пользователь",
        "guest": "Гостевой доступ",
    }
    elements_data = {
        "users": "Пользователи",
        "products": "Товары",
        "orders": "Заказы",
        "access_rules": "Правила доступа",
    }

    roles: dict[str, Role] = {}
    for name, description in roles_data.items():
        role = db.query(Role).filter(Role.name == name).first()
        if not role:
            role = Role(name=name, description=description)
            db.add(role)
            db.flush()
        else:
            role.description = description
            db.add(role)
        roles[name] = role

    elements: dict[str, BusinessElement] = {}
    for code, title in elements_data.items():
        element = db.query(BusinessElement).filter(BusinessElement.code == code).first()
        if not element:
            element = BusinessElement(code=code, title=title)
            db.add(element)
            db.flush()
        else:
            element.title = title
            db.add(element)
        elements[code] = element

    db.commit()

    for role in roles.values():
        for element in elements.values():
            rule = (
                db.query(AccessRule)
                .filter(AccessRule.role_id == role.id, AccessRule.element_id == element.id)
                .first()
            )
            if not rule:
                rule = AccessRule(role_id=role.id, element_id=element.id)

            rule.read_permission = False
            rule.read_all_permission = False
            rule.create_permission = False
            rule.update_permission = False
            rule.update_all_permission = False
            rule.delete_permission = False
            rule.delete_all_permission = False
            db.add(rule)
    db.commit()

    def apply_rule(role_name: str, element_code: str, **kwargs):
        rule = (
            db.query(AccessRule)
            .filter(
                AccessRule.role_id == roles[role_name].id,
                AccessRule.element_id == elements[element_code].id,
            )
            .first()
        )
        for field, value in kwargs.items():
            setattr(rule, field, value)
        db.add(rule)

    all_true = {
        "read_permission": True,
        "read_all_permission": True,
        "create_permission": True,
        "update_permission": True,
        "update_all_permission": True,
        "delete_permission": True,
        "delete_all_permission": True,
    }
    for element_code in elements.keys():
        apply_rule("admin", element_code, **all_true)

    apply_rule(
        "manager",
        "products",
        read_permission=True,
        read_all_permission=True,
        create_permission=True,
        update_permission=True,
        update_all_permission=True,
    )
    apply_rule(
        "manager",
        "orders",
        read_permission=True,
        read_all_permission=True,
        create_permission=True,
        update_permission=True,
        update_all_permission=True,
    )
    apply_rule("manager", "users", read_permission=True)

    apply_rule("user", "users", read_permission=True, update_permission=True, delete_permission=True)
    apply_rule(
        "user",
        "products",
        read_permission=True,
        create_permission=True,
        update_permission=True,
        delete_permission=True,
    )
    apply_rule(
        "user",
        "orders",
        read_permission=True,
        create_permission=True,
        update_permission=True,
        delete_permission=True,
    )

    apply_rule("guest", "products", read_permission=True, read_all_permission=True)
    db.commit()

    admin = db.query(User).filter(User.email == "admin@example.com").first()
    if not admin:
        admin = User(
            role_id=roles["admin"].id,
            first_name="Admin",
            last_name="System",
            email="admin@example.com",
            password_hash=hash_password("Admin123!"),
            is_active=True,
        )
    else:
        admin.role_id = roles["admin"].id
        admin.first_name = "Admin"
        admin.last_name = "System"
        admin.password_hash = hash_password("Admin123!")
        admin.is_active = True
    db.add(admin)

    student = db.query(User).filter(User.email == "student@example.com").first()
    if not student:
        student = User(
            role_id=roles["user"].id,
            first_name="Ivan",
            last_name="Student",
            email="student@example.com",
            password_hash=hash_password("Student123!"),
            is_active=True,
        )
    else:
        student.role_id = roles["user"].id
        student.first_name = "Ivan"
        student.last_name = "Student"
        student.password_hash = hash_password("Student123!")
        student.is_active = True
    db.add(student)

    db.commit()


if __name__ == "__main__":
    wait_for_db()
    Base.metadata.create_all(bind=engine)

    session = SessionLocal()
    try:
        seed_demo_data(session)
        print("Тестовые данные готовы")
        print("admin@example.com / Admin123!")
        print("student@example.com / Student123!")
    finally:
        session.close()
