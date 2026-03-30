# ver4

Небольшой проект под ТЗ на стажировку: FastAPI + PostgreSQL + JWT + роли/права.

## Что реализовано

- регистрация, вход и выход;
- `GET /auth/me`, `PATCH /auth/me`, `DELETE /auth/me`;
- soft delete пользователя (`is_active = false`);
- хранение сессий в `user_sessions` (после logout токен становится невалидным);
- роли, ресурсы и правила доступа (admin CRUD);
- mock-ресурсы `products` и `orders` для проверки ролевой модели.

## По файлам

- `main.py` - роуты и основная логика;
- `models.py` - SQLAlchemy модели;
- `schemas.py` - pydantic схемы запросов/ответов;
- `security.py` - хэш паролей и JWT;
- `database.py` - подключение к БД;
- `seed.py` - начальные данные (роли, правила, тестовые пользователи);
- `mock_store.py` - хранилище mock-данных в памяти;
- `docker-compose.yml`, `Dockerfile` - запуск в docker.

## Быстрый запуск (Docker)

```bash
cd "/home/banderlord/Рабочий стол/Effective_Mobile/ver4"
cp .env.example .env
docker compose up --build
```

Откроется:
- Swagger: `http://localhost:8000/docs`

`seed.py` в docker запускается автоматически перед стартом API.

## Запуск локально (без Docker)

1. Подними PostgreSQL (локально или отдельно в контейнере).
2. Создай `.env`:

```bash
cp .env.example .env
```

3. Создай виртуальное окружение:

```bash
python3 -m venv .venv
source .venv/bin/activate
```

4. Установи зависимости:

```bash
pip install -r requirements.txt
```

5. Заполни тестовые данные:

```bash
python seed.py
```

6. Запусти API:

```bash
uvicorn main:app --reload
```

## Тестовые пользователи

- `admin@example.com / Admin123!`
- `student@example.com / Student123!`
# Effective-Mobile
