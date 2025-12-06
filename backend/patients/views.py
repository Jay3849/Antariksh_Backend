from rest_framework import viewsets, status
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated
from rest_framework.exceptions import ValidationError

from django.contrib.auth import get_user_model
from .models import Patient
from .serializers import PatientSerializer

User = get_user_model()


class PatientViewSet(viewsets.ModelViewSet):
    queryset = Patient.objects.all()
    serializer_class = PatientSerializer
    permission_classes = [IsAuthenticated]

    # -----------------------------------------
    # AUTO LIMIT → Only logged-in user's patient
    # -----------------------------------------
    def get_queryset(self):
        # Only show patient belonging to logged-in user
        return Patient.objects.filter(user=self.request.user)

    # -----------------------------------------
    # HANDLE CREATE (Only if user has no patient)
    # -----------------------------------------
    def create(self, request, *args, **kwargs):
        user = request.user

        # Check if patient already exists for user
        if hasattr(user, "patient_profile"):
            return Response(
                {"detail": "This user already has a patient profile."},
                status=400,
            )

        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        serializer.save(user=user)  # Auto assign logged-in user

        return Response(serializer.data, status=status.HTTP_201_CREATED)

    # -----------------------------------------
    # UPDATE (PATCH / PUT)
    # -----------------------------------------
    def update(self, request, *args, **kwargs):
        instance = self.get_object()
        serializer = self.get_serializer(instance, data=request.data, partial=True)
        serializer.is_valid(raise_exception=True)

        serializer.save()
        return Response(serializer.data, status=200)

    # -----------------------------------------
    # GET SINGLE PATIENT
    # -----------------------------------------
    def retrieve(self, request, *args, **kwargs):
        instance = self.get_object()
        serializer = self.get_serializer(instance)
        return Response(serializer.data, status=200)

