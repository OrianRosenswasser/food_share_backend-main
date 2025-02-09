from django import forms
from .models import Member, FoodPost, FoodRequest

class MemberForm(forms.ModelForm):
    class Meta:
        model = Member
        fields = ['firstname', 'lastname', 'password', 'email']

class FoodPostForm(forms.ModelForm):
    class Meta:
        model = FoodPost
        fields = ['title', 'description', 'quantity', 'photo', 'expiration_date']
        widgets = {
            'expiration_date': forms.DateInput(attrs={'type': 'date'}),
        }

class FoodRequestForm(forms.ModelForm):
    class Meta:
        model = FoodRequest
        fields = ['food_post']
        
    def save(self, commit=True):
        return super().save(commit)