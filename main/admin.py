from django.contrib import admin
from django.utils import timezone

# from .models import Member, FoodPost, FoodRequest, User
from .models import  FoodPost, FoodRequest, User

# Register your models here.
# admin.site.register(Member)
# admin.site.register(FoodPost)
# admin.site.register(FoodRequest)


from .models import User, FoodPost, FoodRequest
from django.contrib import admin
from django.utils.html import format_html
from django.urls import reverse
from .models import FoodRequest


@admin.register(User)
class UserAdmin(admin.ModelAdmin):
    list_display = (
    'email', 'firstname', 'lastname', 'is_active', 'is_staff', 'get_food_posts_count', 'get_food_requests_count')
    list_filter = ('is_active', 'is_staff')
    search_fields = ('email', 'firstname', 'lastname')
    ordering = ('email',)

    fieldsets = (
        (None, {'fields': ('email', 'password')}),
        ('Personal info', {'fields': ('firstname', 'lastname')}),
        ('Permissions', {'fields': ('is_active', 'is_staff', 'is_superuser', 'groups', 'user_permissions')}),
    )

    add_fieldsets = (
        (None, {
            'classes': ('wide',),
            'fields': ('email', 'firstname', 'lastname', 'password1', 'password2'),
        }),
    )


@admin.register(FoodPost)
class FoodPostAdmin(admin.ModelAdmin):
    list_display = ('title', 'posted_by', 'quantity', 'expiration_date', 'collection_point')
    list_filter = ('expiration_date', 'posted_by')
    search_fields = ('title', 'description', 'posted_by__email')
    date_hierarchy = 'expiration_date'
    ordering = ('-expiration_date',)

    fieldsets = (
        ('Basic Information', {
            'fields': ('title', 'description', 'quantity', 'posted_by')
        }),
        ('Details', {
            'fields': ('expiration_date', 'collection_point', 'whatsapp_link', 'photo')
        }),
    )


# @admin.register(FoodRequest)
# class FoodRequestAdmin(admin.ModelAdmin):
#     list_display = ('__str__', 'food_post', 'requested_by')
#     list_filter = ('food_post', 'requested_by')
#     search_fields = ('food_post__title', 'requested_by__email')
#     raw_id_fields = ('food_post', 'requested_by')


@admin.register(FoodRequest)
class FoodRequestAdmin(admin.ModelAdmin):
    list_display = ('request_id', 'food_post_title', 'food_details', 'requester_info', 'request_status')
    list_filter = ('food_post__expiration_date', 'food_post__collection_point')
    search_fields = ('food_post__title', 'requested_by__email', 'requested_by__firstname')
    list_per_page = 20

    def request_id(self, obj):
        return f"Request #{obj.id}"

    request_id.short_description = "ID"

    def food_post_title(self, obj):
        url = reverse('admin:main_foodpost_change', args=[obj.food_post.id])
        return format_html('<a href="{}">{}</a>', url, obj.food_post.title)

    food_post_title.short_description = "Food Item"

    def food_details(self, obj):
        return format_html(
            """
            <div style="min-width: 200px;">
                <strong>Quantity:</strong> {}<br>
                <strong>Collection:</strong> {}<br>
                <strong>Expires:</strong> {}
            </div>
            """,
            obj.food_post.quantity,
            obj.food_post.collection_point,
            obj.food_post.expiration_date.strftime("%Y-%m-%d %H:%M")
        )

    food_details.short_description = "Food Details"

    def requester_info(self, obj):
        if obj.requested_by:
            url = reverse('admin:main_user_change', args=[obj.requested_by.id])
            return format_html(
                """
                <div style="min-width: 200px;">
                    <a href="{}">{} {}</a><br>
                    <small>{}</small>
                </div>
                """,
                url,
                obj.requested_by.firstname,
                obj.requested_by.lastname,
                obj.requested_by.email
            )
        return "Anonymous"

    requester_info.short_description = "Requested By"

    def request_status(self, obj):
        if obj.food_post.expiration_date < timezone.now():
            return format_html(
                '<span style="color: red; font-weight: bold;">Expired</span>'
            )
        return format_html(
            '<span style="color: green; font-weight: bold;">Active</span>'
        )

    request_status.short_description = "Status"

    # Custom fieldsets for the edit form
    fieldsets = (
        ('Request Information', {
            'fields': ('food_post', 'requested_by'),
            'description': 'Basic information about the food request'
        }),
    )

    # Optional: Add actions if needed
    actions = ['mark_as_processed']

    def mark_as_processed(self, request, queryset):
        # Add your processing logic here
        self.message_user(request, f"{queryset.count()} requests marked as processed.")

    mark_as_processed.short_description = "Mark selected requests as processed"