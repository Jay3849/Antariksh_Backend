from django.urls import path
from .views import PatientViewSet

# LIST + CREATE
patient_list = PatientViewSet.as_view({
    'get': 'list',
    'post': 'create',
})

# DETAIL (GET + PATCH only)
patient_detail = PatientViewSet.as_view({
    'get': 'retrieve',
    'patch': 'partial_update',   # you requested this exact logic
})

urlpatterns = [
    path('', patient_list, name='patient-list'),
    path('<int:pk>/', patient_detail, name='patient-detail'),
]
