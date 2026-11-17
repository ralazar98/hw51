"""Авторизация для исходного приложения. Основной UI чата остаётся прежним."""
import asyncio
import hashlib
import hmac
import os
import secrets
import sqlite3
import time

import flet as ft
from api.openrouter import OpenRouterClient, verify_openrouter_balance

DB_PATH = "chat_cache.db"


class AuthStore:
    def __init__(self, db_path=DB_PATH):
        self.db_path = db_path
        with sqlite3.connect(db_path) as db:
            db.execute("""CREATE TABLE IF NOT EXISTS app_auth (
                id INTEGER PRIMARY KEY CHECK (id = 1),
                api_key TEXT NOT NULL,
                pin_salt BLOB NOT NULL,
                pin_hash BLOB NOT NULL,
                demo INTEGER NOT NULL DEFAULT 0
            )""")
        if os.name == "posix":
            os.chmod(db_path, 0o600)

    def get(self):
        with sqlite3.connect(self.db_path) as db:
            return db.execute("SELECT api_key, pin_salt, pin_hash, demo FROM app_auth WHERE id=1").fetchone()

    def save(self, key, pin, demo=False):
        if len(pin) != 4 or not pin.isdecimal():
            raise ValueError("PIN должен состоять из четырёх цифр")
        salt = os.urandom(16)
        digest = hashlib.pbkdf2_hmac("sha256", pin.encode(), salt, 220000)
        with sqlite3.connect(self.db_path) as db:
            db.execute("REPLACE INTO app_auth VALUES (1, ?, ?, ?, ?)", (key, salt, digest, int(demo)))

    def check_pin(self, pin):
        record = self.get()
        if not record:
            return False
        digest = hashlib.pbkdf2_hmac("sha256", pin.encode(), record[1], 220000)
        return hmac.compare_digest(digest, record[2])

    def clear(self):
        with sqlite3.connect(self.db_path) as db:
            db.execute("DELETE FROM app_auth WHERE id=1")


class DemoClient:
    """No network requests; demonstration of the existing chat UI only."""
    available_models = [{"id": "demo", "name": "Демо-модель (без API)"}]

    def get_balance(self):
        return "ДЕМО (без оплаты)"

    def send_message(self, message, model):
        return {"choices": [{"message": {"content":
            "[ДЕМО] Это тестовый ответ. Запрос в OpenRouter не отправлялся. "
            "Ваше сообщение: " + message}}], "usage": {"total_tokens": 0}}


class AuthController:
    def __init__(self, page):
        self.page = page
        self.store = AuthStore()
        self.failed = 0
        self.lock_until = 0
        self.pending_pin = None

    def show(self):
        if self.store.get():
            self.pin_screen()
        else:
            self.key_screen()

    def frame(self, title, *controls):
        self.page.title = "AI Chat — авторизация"
        self.page.theme_mode = ft.ThemeMode.DARK
        self.page.clean()
        self.page.add(ft.Container(
            content=ft.Column([ft.Icon(ft.Icons.LOCK_OUTLINE, size=44, color=ft.Colors.BLUE_400),
                               ft.Text(title, size=24, weight=ft.FontWeight.BOLD), *controls],
                              horizontal_alignment=ft.CrossAxisAlignment.CENTER, spacing=18),
            alignment=ft.alignment.center, expand=True, padding=24))
        self.page.update()

    def key_screen(self):
        key = ft.TextField(label="API-ключ OpenRouter", password=True, can_reveal_password=True, width=400)
        status = ft.Text("", color=ft.Colors.RED_300, text_align=ft.TextAlign.CENTER)
        submit = ft.ElevatedButton("Проверить ключ и создать PIN")
        demo = ft.OutlinedButton("Демо-вход без баланса")

        async def register(e):
            value = (key.value or "").strip()
            submit.disabled = True
            status.value = "Проверяем ключ и баланс OpenRouter..."
            self.page.update()
            try:
                await asyncio.to_thread(verify_openrouter_balance, value)
                self.create_pin(value, False)
            except Exception as exc:
                status.value = str(exc)
                submit.disabled = False
                self.page.update()

        def demo_register(e):
            self.create_pin("DEMO_MODE", True)

        submit.on_click = register
        demo.on_click = demo_register
        self.frame("Первый вход",
                   ft.Text("Введите ключ OpenRouter с положительным балансом."),
                   key, submit,
                   ft.Text("Или проверьте работу PIN без оплаты и API-запросов:"),
                   demo, status)

    def create_pin(self, key, demo):
        pin = f"{secrets.randbelow(10000):04d}"
        self.store.save(key, pin, demo)
        def finish(e):
            self.open_chat()
        self.frame("Ваш новый PIN-код",
                   ft.Text(pin, size=42, weight=ft.FontWeight.BOLD, selectable=True),
                   ft.Text("Запомните PIN: он показывается только сейчас."),
                   ft.Text("ДЕМО: запросы к AI будут имитироваться." if demo else "API-ключ проверен."),
                   ft.ElevatedButton("Запомнил — открыть чат", on_click=finish))

    def pin_screen(self):
        pin = ft.TextField(label="Четырёхзначный PIN", password=True,
                           width=250, max_length=4, keyboard_type=ft.KeyboardType.NUMBER)
        status = ft.Text("", color=ft.Colors.RED_300)

        def login(e):
            now = time.monotonic()
            if now < self.lock_until:
                status.value = f"Слишком много попыток. Повторите через {int(self.lock_until-now)+1} сек."
            elif self.store.check_pin(pin.value or ""):
                self.failed = 0
                self.open_chat()
                return
            else:
                self.failed += 1
                status.value = "Неверный PIN-код"
                if self.failed >= 5:
                    self.lock_until = now + 30
                    self.failed = 0
                    status.value = "5 ошибок. Вход заблокирован на 30 секунд."
            pin.value = ""
            self.page.update()

        self.frame("Вход по PIN", pin,
                   ft.ElevatedButton("Войти", on_click=login),
                   ft.TextButton("Сбросить ключ / деморежим", on_click=self.confirm_reset),
                   status)

    def confirm_reset(self, e):
        def cancel(e):
            self.page.close(dialog)
        def reset(e):
            self.page.close(dialog)
            self.store.clear()
            self.key_screen()
        dialog = ft.AlertDialog(modal=True, title=ft.Text("Сброс авторизации"),
                                content=ft.Text("Удалить сохранённый ключ и PIN? История чата останется."),
                                actions=[ft.TextButton("Отмена", on_click=cancel),
                                         ft.TextButton("Сбросить", on_click=reset)])
        self.page.open(dialog)

    def open_chat(self):
        from main import ChatApp
        record = self.store.get()
        if not record:
            self.key_screen()
            return
        client = DemoClient() if record[3] else OpenRouterClient(api_key=record[0])
        # Remove the PIN screen before showing the original chat UI.
        self.page.clean()
        app = ChatApp(api_client=client)
        app.main(self.page)

        # Keep the logout bar inside the existing chat column, not as
        # a second root control that changes the layout.
        auth_bar = ft.Row(
            controls=[
                ft.Text("ДЕМО-РЕЖИМ" if record[3] else "OpenRouter",
                        color=ft.Colors.AMBER_400 if record[3] else ft.Colors.GREEN_400),
                ft.TextButton("Сменить ключ / выйти", on_click=self.confirm_reset),
            ],
            alignment=ft.MainAxisAlignment.CENTER,
        )
        app.main_column.controls.insert(0, auth_bar)
        self.page.update()
