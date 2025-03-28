from django.db import models
from django.conf import settings

class Email(models.Model):
    adresse = models.EmailField(max_length=255)
    objet = models.CharField(max_length=255)
    piece_jointe = models.FileField(
        upload_to='emails/attachments/', 
        null=True, 
        blank=True
    )
    nom_utilisateur = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name='emails'
    )
    date_creation = models.DateTimeField(auto_now_add=True)
    date_modification = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ['-date_creation']

    def __str__(self):
        return f"{self.adresse} - {self.objet}"