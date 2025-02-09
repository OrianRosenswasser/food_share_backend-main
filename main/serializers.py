# from rest_framework import serializers
# from .models import Member, FoodPost, FoodRequest, User
#
# class MemberSerializer(serializers.ModelSerializer):
#     class Meta:
#         model = Member
#         fields = '__all__'
#
# class FoodPostSerializer(serializers.ModelSerializer):
#     class Meta:
#         model = FoodPost
#         fields = '__all__'  # Include all fields in the serialized data
#         extra_kwargs = {
#             'id': {'required': False},  # Make the ID optional
#             'quantity': {'required': False},  # Optional quantity field
#             'posted_by': {'required': False},  # Optional posted_by field
#             'expiration_date': {'required': False},  # Optional expiration_date
#             'photo': {'required': False},  # Optional photo field
#             'whatsapp_link': {'required': False},  # Optional whatsapp_link field
#             'collection_point': {'required': False},  # Optional collection_point field
#         }
#
# class FoodRequestSerializer(serializers.ModelSerializer):
#     class Meta:
#         model = FoodRequest
#         fields = ['food_post']
#
#     def create(self, validated_data):
#         validated_data['requested_by'] = None
#         return super().create(validated_data)
#
# class UserSerializer(serializers.ModelSerializer):
#     class Meta:
#         model = User
#         fields = ['firstname', 'lastname', 'email', 'password']
#         extra_kwargs = {
#             'password': {'write_only': True},  # Ensure password is write-only
#         }
#
#     def create(self, validated_data):
#         # Hash the password before saving the user
#         validated_data['password'] = validated_data['password']
#         print('created2')
#         return super().create(validated_data)
#
# class RegisterSerializer(serializers.ModelSerializer):
#     class Meta:
#         model = User
#         fields = ['username', 'password', 'email']

from rest_framework import serializers
from django.contrib.auth.hashers import make_password
# from .models import User, Member, FoodPost, FoodRequest
from .models import User, FoodPost, FoodRequest


class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['id', 'email', 'firstname', 'lastname', 'password','is_staff']
        extra_kwargs = {
            'password': {'write_only': True},
            'is_staff': {'read_only': True},
        }

    def create(self, validated_data):
        validated_data['password'] = make_password(validated_data.get('password'))
        return super().create(validated_data)


# class MemberSerializer(serializers.ModelSerializer):
#     class Meta:
#         model = Member
#         fields = ['id', 'firstname', 'lastname', 'email']
#         extra_kwargs = {
#             'password': {'write_only': True}  # Don't send password back in responses
#         }


class FoodPostSerializer(serializers.ModelSerializer):
    posted_by = UserSerializer(read_only=True)

    # posted_by = MemberSerializer(read_only=True)

    class Meta:
        model = FoodPost
        fields = ['id', 'title', 'description', 'quantity', 'posted_by',
                  'expiration_date', 'photo', 'collection_point', 'whatsapp_link']
        extra_kwargs = {
            'id': {'read_only': True},
            'posted_by': {'read_only': True},
            'photo': {'required': False},
            'whatsapp_link': {'required': False},
        }


class FoodRequestSerializer(serializers.ModelSerializer):
    requested_by = UserSerializer(read_only=True)
    # requested_by = MemberSerializer(read_only=True)
    # food_post = FoodPostSerializer(read_only=True)
    food_post = serializers.PrimaryKeyRelatedField(queryset=FoodPost.objects.all()) # Use PrimaryKeyRelatedField
    # food_post = FoodPostSerializer()

    class Meta:
        model = FoodRequest
        fields = ['id', 'food_post', 'requested_by']
        extra_kwargs = {
            'id': {'read_only': True},
            'requested_by': {'read_only': True},
        }

    def create(self, validated_data):
        validated_data['requested_by'] = self.context['request'].user
        return super().create(validated_data)


class RegisterSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['email', 'firstname', 'lastname', 'password']
        extra_kwargs = {
            'password': {'write_only': True},
        }

    def create(self, validated_data):
        user = User.objects.create_user(
            email=validated_data['email'],
            password=validated_data['password'],
            firstname=validated_data.get('firstname', ''),
            lastname=validated_data.get('lastname', '')
        )
        return user
