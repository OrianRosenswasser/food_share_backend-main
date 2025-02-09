# # models.py
# from datetime import datetime
# from django.db import models
# from django.utils import timezone
# from django.contrib.auth.hashers import make_password, check_password

# class Member(models.Model):
#     firstname = models.CharField(max_length=255)
#     lastname = models.CharField(max_length=255)
#     password = models.CharField(max_length=255, default="default_password")
#     email = models.EmailField(unique=True, default="default@example.com")

#     def __str__(self):
#         return f"{self.firstname} {self.lastname}"

#     def get_food_posts_count(self):
#         return self.foodpost_set.count()

#     def get_food_requests_count(self):
#         return self.foodrequest_set.count()

# class FoodPost(models.Model):
#     title = models.CharField(max_length=100)
#     description = models.TextField()
#     quantity = models.PositiveIntegerField()
#     posted_by = models.ForeignKey(Member, on_delete=models.CASCADE, related_name='posts')
#     expiration_date = models.DateTimeField(default=timezone.now)
#     photo = models.ImageField(upload_to='food_posts/', null=True, blank=True)
#     collection_point = models.CharField(max_length=255, null=False, default='Unknown')
#     whatsapp_link = models.CharField(max_length=15, null=True, blank=True)    

#     def __str__(self):
#         return f"{self.title}"

# class FoodRequest(models.Model):
#     food_post = models.ForeignKey(FoodPost, on_delete=models.CASCADE)
#     requested_by = models.ForeignKey(Member, on_delete=models.CASCADE, null=True, blank=True)

#     def __str__(self):
#         return f"Request for {self.food_post} by {self.requested_by or 'Unknown'}"


from datetime import datetime
from django.db import models
from django.utils import timezone
from django.contrib.auth.models import AbstractBaseUser, BaseUserManager, PermissionsMixin

# AUTH_USER_MODEL = 'main.User'


class UserManager(BaseUserManager):
    def create_user(self, email, password=None, **extra_fields):
        if not email:
            raise ValueError("The Email field must be set.")
        email = self.normalize_email(email)
        extra_fields.setdefault("is_staff", False)
        extra_fields.setdefault("is_superuser", False)
        user = self.model(email=email, **extra_fields)
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, email, password=None, **extra_fields):
        extra_fields.setdefault("is_staff", True)
        extra_fields.setdefault("is_superuser", True)
        return self.create_user(email, password, **extra_fields)


class User(AbstractBaseUser, PermissionsMixin):
    email = models.EmailField(unique=True)
    firstname = models.CharField(max_length=255)
    lastname = models.CharField(max_length=255)
    is_active = models.BooleanField(default=True)
    is_staff = models.BooleanField(default=False)

    groups = models.ManyToManyField(
        'auth.Group',
        related_name='custom_user_set',  # Avoids conflict with auth.User.groups
        blank=True
    )
    user_permissions = models.ManyToManyField(
        'auth.Permission',
        related_name='custom_user_permissions_set',  # Avoids conflict with auth.User.user_permissions
        blank=True
    )

    objects = UserManager()

    USERNAME_FIELD = "email"
    REQUIRED_FIELDS = ["firstname", "lastname"]

    def __str__(self):
        return f"{self.firstname} {self.lastname} ({self.email})"

    def get_food_posts_count(self):
        """Count the number of food posts created by this user."""
        return self.posts.count()  # Use related_name='posts' from FoodPost

    def get_food_requests_count(self):
        """Count the number of food requests made by this user."""
        return self.foodrequest_set.count()  # Default related_name


# class Member(models.Model):
#     firstname = models.CharField(max_length=255)
#     lastname = models.CharField(max_length=255)
#     password = models.CharField(max_length=255, default="default_password")
#     email = models.EmailField(unique=True, default="default@example.com")
#
#     def __str__(self):
#         return f"{self.firstname} {self.lastname}"
#
#     def get_food_posts_count(self):
#         return self.foodpost_set.count()
#
#     def get_food_requests_count(self):
#         return self.foodrequest_set.count()


class FoodPost(models.Model):
    title = models.CharField(max_length=100)
    description = models.TextField()
    quantity = models.PositiveIntegerField()
    # posted_by = models.ForeignKey(Member, on_delete=models.CASCADE, related_name='posts')
    posted_by = models.ForeignKey(User, on_delete=models.CASCADE, related_name='posts')  # Updated
    expiration_date = models.DateTimeField(default=timezone.now)
    photo = models.ImageField(upload_to='food_posts/', null=True, blank=True)
    collection_point = models.CharField(max_length=255, null=False, default='Unknown')
    whatsapp_link = models.CharField(max_length=15, null=True, blank=True)

    def __str__(self):
        return f"{self.title}"


class FoodRequest(models.Model):
    food_post = models.ForeignKey(FoodPost, on_delete=models.CASCADE)
    # requested_by = models.ForeignKey(Member, on_delete=models.CASCADE, null=True, blank=True)
    requested_by = models.ForeignKey(User, on_delete=models.CASCADE, null=True, blank=True)  # Updated

    def __str__(self):
        return f"Request for {self.food_post} by {self.requested_by or 'Unknown'}"


# Email: admin@gmail.com password admin
#
