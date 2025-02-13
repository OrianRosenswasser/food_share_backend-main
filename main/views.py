
from rest_framework import status, permissions, generics
from rest_framework.decorators import api_view, permission_classes
from rest_framework.exceptions import PermissionDenied
from rest_framework.response import Response
from rest_framework_simplejwt.tokens import RefreshToken
from django.contrib.auth import authenticate
from .serializers import UserSerializer, FoodPostSerializer, FoodRequestSerializer
from .models import FoodPost, FoodRequest, User
from rest_framework import status, generics, permissions
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAdminUser
from django.contrib.auth import get_user_model
from django.db.models import Count
from rest_framework.response import Response


@api_view(['GET'])
@permission_classes([IsAdminUser])
def user_stats(request):
    users = request.user.__class__.objects.annotate(
        posts_count=Count('posts', distinct=True),
        requests_count=Count('foodrequest', distinct=True)
    ).values(
        'id', 'email', 'firstname', 'lastname',
        'is_active', 'is_staff', 'posts_count', 'requests_count'
    )
    return Response(list(users))


@api_view(['POST'])
@permission_classes([permissions.AllowAny])
def register(request):
    serializer = UserSerializer(data=request.data)
    if serializer.is_valid():
        user = serializer.save()
        refresh = RefreshToken.for_user(user)
        return Response({
            'user': serializer.data,
            'refresh': str(refresh),
            'access': str(refresh.access_token),
        }, status=status.HTTP_201_CREATED)
    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


@api_view(['POST'])
@permission_classes([permissions.AllowAny])
def login(request):
    email = request.data.get('email')
    password = request.data.get('password')
    user = authenticate(email=email, password=password)

    if user:
        refresh = RefreshToken.for_user(user)
        return Response({
            'user': UserSerializer(user).data,
            'refresh': str(refresh),
            'access': str(refresh.access_token),
        })
    return Response({'error': 'Invalid credentials'}, status=status.HTTP_401_UNAUTHORIZED)


@api_view(['GET'])
@permission_classes([permissions.IsAuthenticated])
def food_feed(request):
    posts = FoodPost.objects.all().order_by('-expiration_date')
    serializer = FoodPostSerializer(posts, many=True)
    return Response(serializer.data)


@api_view(['POST'])
@permission_classes([permissions.IsAuthenticated])
def post_food(request):
    serializer = FoodPostSerializer(data=request.data)
    if serializer.is_valid():
        serializer.save(posted_by=request.user)
        return Response(serializer.data, status=status.HTTP_201_CREATED)
    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class FoodPostDetailView(generics.RetrieveUpdateDestroyAPIView):
    queryset = FoodPost.objects.all()
    serializer_class = FoodPostSerializer
    permission_classes = [permissions.IsAuthenticated]

    def perform_update(self, serializer):
        if serializer.instance.posted_by == self.request.user:
            serializer.save()
        else:
            raise PermissionDenied()

    def perform_destroy(self, instance):
        if instance.posted_by == self.request.user:
            instance.delete()
        else:
            raise PermissionDenied()


class FoodRequestListCreateView(generics.ListCreateAPIView):
    queryset = FoodRequest.objects.all()
    serializer_class = FoodRequestSerializer
    # permission_classes = [permissions.IsAuthenticatedOrReadOnly]
    permission_classes = [permissions.IsAuthenticated]

    def perform_create(self, serializer):
        serializer.save(requested_by=self.request.user)


class FoodRequestRetrieveUpdateDestroyView(generics.RetrieveUpdateDestroyAPIView):
    queryset = FoodRequest.objects.all()
    serializer_class = FoodRequestSerializer
    permission_classes = [permissions.IsAuthenticated]

    def perform_update(self, serializer):
        if serializer.instance.requested_by == self.request.user:
            serializer.save()
        else:
            raise PermissionDenied("You do not have permission to update this request.")

    def perform_destroy(self, instance):
        if instance.requested_by == self.request.user:
            instance.delete()
        else:
            raise PermissionDenied("You do not have permission to delete this request.")


class FoodRequestListView(generics.ListAPIView):
    serializer_class = FoodRequestSerializer
    permission_classes = [permissions.IsAuthenticated]

    def get_queryset(self):
        user = self.request.user
        
        return FoodRequest.objects.filter(requested_by=user) | FoodRequest.objects.filter(food_post__posted_by=user)

