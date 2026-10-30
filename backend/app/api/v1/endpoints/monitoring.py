"""WebAudit 360 — Continuous Monitoring Schedules API
Author: Harsh Patel
"""

from typing import List
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from backend.app.core.database import get_db
from backend.app.models.entities import MonitoringSchedule, User
from backend.app.schemas import ScheduleCreate, ScheduleResponse, StatusResponse
from backend.app.api.v1.dependencies import get_current_user

router = APIRouter(prefix="/monitoring", tags=["Monitoring"])


@router.get("", response_model=List[ScheduleResponse])
async def list_monitoring_schedules(
    user: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_db)
):
    """Lists active recurring audit schedules for the authenticated user."""
    query = select(MonitoringSchedule)
    result = await session.execute(query)
    schedules = result.scalars().all()
    return [ScheduleResponse.model_validate(s) for s in schedules]


@router.post("", response_model=ScheduleResponse, status_code=status.HTTP_201_CREATED)
async def create_monitoring_schedule(
    payload: ScheduleCreate,
    user: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_db)
):
    """Registers a recurring audit schedule for continuous health tracking."""
    schedule = MonitoringSchedule(
        project_id=payload.project_id,
        target_url=payload.target_url,
        interval_days=payload.interval_days,
        alert_on_regression=payload.alert_on_regression,
        is_active=True
    )
    session.add(schedule)
    await session.commit()
    await session.refresh(schedule)
    return ScheduleResponse.model_validate(schedule)


@router.delete("/{schedule_id}", response_model=StatusResponse)
async def delete_monitoring_schedule(
    schedule_id: int,
    user: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_db)
):
    """Cancels and removes a recurring audit schedule."""
    result = await session.execute(
        select(MonitoringSchedule).where(MonitoringSchedule.id == schedule_id)
    )
    schedule = result.scalars().first()
    if not schedule:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Schedule not found.")

    await session.delete(schedule)
    await session.commit()
    return StatusResponse(success=True, message="Schedule deleted successfully.")

