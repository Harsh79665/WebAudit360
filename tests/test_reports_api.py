"""WebAudit 360 — Reports & Headless PDF Generation Tests
Author: Harsh Patel
"""

import pytest
import httpx

from backend.app.main import app
from backend.app.core.database import AsyncSessionLocal
from backend.app.models.entities import Audit, AuditStatus, DeviceProfile, ScanMode


@pytest.mark.asyncio
async def test_pdf_report_stream_and_attachment_header():
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
        # Create an audit record directly in db
        async with AsyncSessionLocal() as session:
            test_audit = Audit(
                target_url="https://example.com/pdf-test",
                scan_mode=ScanMode.SINGLE_PAGE,
                device_profile=DeviceProfile.DESKTOP,
                status=AuditStatus.COMPLETED,
                overall_score=88.5,
                score_performance=92.0,
                score_seo=85.0,
                score_accessibility=90.0,
                score_security=87.0,
                score_technical=95.0,
                pages_scanned=1,
                pages_discovered=1,
                pages_failed=0,
                raw_results={}
            )
            session.add(test_audit)
            await session.commit()
            await session.refresh(test_audit)
            audit_id = test_audit.id

        # 1. Test binary PDF download endpoint
        res = await client.get(f"/api/v1/reports/{audit_id}/pdf")
        assert res.status_code == 200
        assert res.headers["content-type"] == "application/pdf"
        assert f'attachment; filename="webaudit360_report_{audit_id}.pdf"' in res.headers["content-disposition"]
        assert len(res.content) > 100
        # Valid PDF starts with %PDF
        assert res.content.startswith(b"%PDF")

        # 2. Test HTML printable report endpoint
        res_html = await client.get(f"/api/v1/reports/{audit_id}/html")
        assert res_html.status_code == 200
        assert "text/html" in res_html.headers["content-type"]
        assert "WebAudit 360" in res_html.text
        assert "Overall Health Rating" in res_html.text
