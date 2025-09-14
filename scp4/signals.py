from django.db.models.signals import post_save
from django.dispatch import receiver
from django.contrib.auth.models import User
from .models import UserProfile, ScanResult

@receiver(post_save, sender=User)
def create_user_profile(sender, instance, created, **kwargs):
    if created:
        UserProfile.objects.get_or_create(user=instance)

@receiver(post_save, sender=ScanResult)
def update_user_profile_stats(sender, instance, created, **kwargs):
    if created and hasattr(instance.user, 'profile'):
        instance.user.profile.update_scan_stats()