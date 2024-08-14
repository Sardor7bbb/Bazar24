from django.contrib.auth import authenticate
from django.core.mail import send_mail
from rest_framework import serializers

from user.models import UserModel, VIA_EMAIL, ConfirmationModel, CODE_VERIFIED
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer


class CreateUserSerializer(serializers.ModelSerializer):
    confirm_password = serializers.CharField(write_only=True)

    class Meta:
        model = UserModel
        fields = ['first_name', 'last_name', 'email', 'phone_number', 'password', 'confirm_password']
        extra_kwargs = {
            'password': {'write_only': True},
        }

    def create(self, validated_data):
        validated_data.pop('confirm_password')
        user = UserModel.objects.create_user(
            email=validated_data.get('email'),
            phone_number=validated_data.get('phone_number'),
            password=validated_data.get('password'),
            first_name=validated_data.get('first_name'),
            last_name=validated_data.get('last_name'),
        )

        refresh = RefreshToken.for_user(user)
        verify_code = user.create_verify_code(VIA_EMAIL)

        send_code_to_email(user.email, verify_code)

        return {
            'user': user.pk,
            'refresh': str(refresh),
            'access': str(refresh.access_token),
        }

    def to_representation(self, instance):
        return {
            'user': instance['user'],
            'refresh': instance['refresh'],
            'access': instance['access'],
        }

    def send_code_to_email(email, code):
        send_mail(
            'Verification Code',
            f'Your verification code is {code}',
            'emailizi yozas@gmail.com',
            [email],
            fail_silently=False,
        )


class VerifyCodeSerializer(serializers.Serializer):
    code = serializers.CharField()

    def validate_code(self, value):
        if not ConfirmationModel.objects.filter(code=value, is_confirmed=False).exists():
            raise serializers.ValidationError("Invalid or expired code.")
        return value

    def to_representation(self, instance):
        return {
            'user': instance['user'],
            'refresh': instance['refresh'],
            'access': instance['access'],
        }

    def save(self, **kwargs):
        code = self.validated_data['code']
        confirmation = ConfirmationModel.objects.get(code=code)
        confirmation.is_confirmed = True
        confirmation.save()
        confirmation.user.auth_status = CODE_VERIFIED
        confirmation.user.save()
        return confirmation.user


class LoginSerializer(TokenObtainPairSerializer):
    def __init__(self, *args, **kwargs):
        super(LoginSerializer, self).__init__(*args, **kwargs)
        self.fields['email'] = serializers.CharField(max_length=255, required=True)
        self.fields['phone_number'] = serializers.CharField(max_length=15, null=True)

    def validate(self, attrs):
        userinput = attrs.get('Phone number or Email')
        password = attrs.get('password')

        if userinput.endswith('@gmail.com'):
            user = UserModel.objects.filter(email=userinput).first()
        else:
            user = UserModel.objects.filter(username=userinput).first()

        if user is None:
            raise serializers.ValidationError("Username is invalid")

        auth_user = authenticate(username=user.username, password=password)
        if auth_user is None:
            raise serializers.ValidationError("Username or Password is invalid")

        refresh = RefreshToken.for_user(auth_user)
        response = {
            "status": True,
            "refresh": str(refresh),
            "access": str(refresh.access_token)
        }
        return response


class UpdateUserSerializer(serializers.ModelSerializer):
    first_name = serializers.CharField(max_length=255, write_only=True, required=True)
    last_name = serializers.CharField(max_length=255, write_only=True, required=True)
    phone_number = serializers.CharField(max_length=255, write_only=True, required=True)
    email = serializers.EmailField(write_only=True, required=True)

    class Meta:
        model = UserModel
        fields = ['first_name', 'last_name', 'phone_number', 'email']

    def validate_username(self, username):
        if UserModel.objects.filter(username=username).exists():
            response = {
                "success": False,
                "message": "Username is already gotten"
            }
            raise serializers.ValidationError(response)
        return username

    def update(self, instance, validated_data):
        instance.username = validated_data.get('phone_number', instance.username)
        instance.first_name = validated_data.get('first_name', instance.first_name)
        instance.last_name = validated_data.get('last_name', instance.last_name)
        instance.email = validated_data.get('email', instance.email)
        return instance


class LogoutSerializer(serializers.Serializer):
    refresh = serializers.CharField()


class UserListViewSerializer(serializers.ModelSerializer):
    class Meta:
        model = UserModel
        fields = '__all__'


class ForgetPasswordSerializer(serializers.Serializer):
    email = serializers.CharField(write_only=True, required=True)

    def validate(self, attrs):
        email_phone_number = attrs.get('email')
        response = {"success": False}
        if not email_phone_number:
            response = {"message": "Email or phone number is required"}
            raise serializers.ValidationError(response)

        user = UserModel.objects.filter(Q(email=email_phone_number) | Q(phone_number=email_phone_number))
        if not user.exists():
            response["message"] = "User not found"
            raise serializers.ValidationError(response)

        attrs["user"] = user.first()
        return attrs
