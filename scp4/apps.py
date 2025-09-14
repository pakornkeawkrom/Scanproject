from django.apps import AppConfig


class Scp4Config(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'scp4'

    def ready(self):
        import scp4.signals  # ปิดชั่วคราว
        pass