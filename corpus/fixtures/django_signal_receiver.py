from django.dispatch import receiver
from django.db.models.signals import post_save


@receiver(post_save)
def on_save(sender, **kwargs):
    return None
