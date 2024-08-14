import random
import uuid
from datetime import timedelta

from django.contrib.auth.models import AbstractUser
from django.db import models
from django.utils import timezone

from shared.models import BaseModel

VIA_EMAIL, VIA_PHONE = "VIA_EMAIL", "VIA_PHONE"
USER, SELLER, MANAGER, ADMIN = "USER", "SELLER", "MANAGER", "ADMIN"
NEW, CODE_VERIFIED, DONE, PHOTO = "NEW", "CODE_VERIFIED", "DONE", "PHOTO"


class UserModel(AbstractUser, BaseModel):
    AUTH_TYPES = (
        (VIA_EMAIL, VIA_EMAIL),
        (VIA_PHONE, VIA_PHONE)
    )

    AUTH_STATUSES = (
        (NEW, NEW),
        (CODE_VERIFIED, CODE_VERIFIED),
        (DONE, DONE),
    )

    USER_ROLES = (
        (ADMIN, ADMIN),
        (MANAGER, MANAGER),
        (USER, USER),
        (SELLER, SELLER)
    )

    auth_type = models.CharField(max_length=128, choices=AUTH_TYPES, default=VIA_EMAIL)
    auth_status = models.CharField(max_length=128, choices=AUTH_STATUSES, default=NEW)
    user_role = models.CharField(max_length=128, choices=USER_ROLES, default=USER)

    phone_number = models.CharField(max_length=15, null=True)

    @property
    def full_name(self):
        return f"{self.first_name} {self.last_name}"

    def check_pass(self):
        if not self.password:
            self.password = f"password-{uuid.uuid4()}"

    def check_email(self):
        self.email = str(self.email).lower()

    def hashing_password(self):
        if not self.password.startswith('pbkdf2_sha256'):
            self.set_password(self.password)

    def clean(self):
        self.check_username()
        self.check_pass()
        self.check_email()
        self.hashing_password()

    def save(self, *args, **kwargs):
        if not self.pk:
            self.clean()
        super(UserModel, self).save(*args, **kwargs)

    def create_verify_code(self, verify_type):
        code = "".join([str(random.randint(1, 100) % 10) for _ in range(4)])
        ConfirmationModel.objects.create(
            code=code,
            user=self,
            verify_type=verify_type
        )
        return code

    def token(self):
        refresh = RefreshToken.for_user(self)
        response = {
            'access_token': str(refresh.access_token),
            'refresh_token': str(refresh)
        }
        return response


EMAIL_EXPIRATION_TIME = 4
PHONE_EXPIRATION_TIME = 2


class ConfirmationModel(BaseModel):
    VERIFY_TYPES = (
        (VIA_EMAIL, VIA_EMAIL),
        (VIA_PHONE, VIA_PHONE)
    )

    verify_type = models.CharField(max_length=128, choices=VERIFY_TYPES, default=VIA_EMAIL)
    user = models.ForeignKey(UserModel, on_delete=models.CASCADE, related_name='verification_codes')
    expiration_time = models.DateField()
    is_confirmed = models.BooleanField(default=False)
    code = models.CharField(max_length=4, default=0000)

    def save(self, *args, **kwargs):
        if not self.pk:
            if self.verify_type == VIA_EMAIL:
                self.expiration_time = timezone.now() + timedelta(minutes=EMAIL_EXPIRATION_TIME)
            else:
                self.expiration_time = timezone.now() + timedelta(minutes=PHONE_EXPIRATION_TIME)
        super(ConfirmationModel, self).save(*args, **kwargs)