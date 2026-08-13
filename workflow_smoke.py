from __future__ import annotations

import hashlib
import io
import os
import tempfile
from pathlib import Path


def main() -> None:
    with tempfile.TemporaryDirectory(prefix="esense-next-") as temp:
        os.environ["ESENSE_DB_PATH"] = str(Path(temp) / "esense.db")
        os.environ["ESENSE_EVIDENCE_PATH"] = str(Path(temp) / "evidence")
        os.environ["MICROSOFT_TENANT_ID"] = "tenant-test"
        os.environ["MICROSOFT_ALLOWED_DOMAINS"] = "example.edu"
        os.environ["MICROSOFT_CLIENT_ID"] = "client-test"
        os.environ["MICROSOFT_CLIENT_SECRET"] = "secret-test"
        os.environ["ESENSE_MIDNIGHT_ENABLED"] = "true"
        os.environ["ESENSE_MIDNIGHT_NETWORK"] = "preprod"
        os.environ["ESENSE_MIDNIGHT_CONTRACT_ADDRESS"] = "contract_test_receipt_registry"
        os.environ["ESENSE_MIDNIGHT_WORKER_TOKEN"] = "worker-test-token"
        import app as esense

        esense.app.config.update(TESTING=True, SESSION_COOKIE_SECURE=False)
        login_page = esense.app.test_client().get("/login")
        assert login_page.status_code == 200
        login_text = login_page.get_data(as_text=True)
        assert "Fortsett med Microsoft" in login_text
        assert "Ingen innloggingsleverandør er konfigurert" not in login_text
        assert "data-language-select" in login_text
        assert "<h1>FieldSeal</h1>" in login_text
        assert "/static/i18n.js?v=22" in login_text
        i18n_asset = esense.app.test_client().get("/static/i18n.js?v=22")
        assert i18n_asset.status_code == 200
        i18n_text = i18n_asset.get_data(as_text=True)
        assert '"Oppdrag og dokumentasjon": "Assignments and documentation"' in i18n_text
        assert '"Forskrift": "Regulation"' in i18n_text
        assert '"Innstillinger": "Settings"' in i18n_text
        assert '"Stilling eller fagrolle": "Position or professional role"' in i18n_text
        assert '"Privat i FieldSeal": "Private in FieldSeal"' in i18n_text
        assert '"Dokumentforpliktelsen er bekreftet på Midnight. Rapportinnhold og personopplysninger forblir private i FieldSeal.": "The document commitment is confirmed on Midnight. Report content and personal data remain private in FieldSeal."' in i18n_text
        users = {
            "provider": ("usr_provider", "provider@example.test", "Oppdragsgiver"),
            "worker": ("usr_worker", "worker@example.test", "Arbeidstaker"),
            "worker2": ("usr_worker2", "worker2@example.test", "Arbeidstaker To"),
            "reviewer": ("usr_reviewer", "reviewer@example.test", "Vurderer"),
            "outsider": ("usr_outsider", "outsider@example.test", "Utenforstaende"),
            "joiner": ("usr_joiner", "joiner@example.test", "Nytt medlem"),
        }
        timestamp = esense.now_iso()
        with esense.db() as connection:
            for key, (user_id, email, name) in users.items():
                connection.execute(
                    "INSERT INTO users (id, google_sub, email, display_name, profile_json, created_at, updated_at) VALUES (?, ?, ?, ?, '{}', ?, ?)",
                    (user_id, f"google-{key}", email, name, timestamp, timestamp),
                )

        microsoft_identity = esense.microsoft_identity_from_claims(
            {
                "tid": "tenant-test",
                "oid": "instructor-object-id",
                "preferred_username": "instructor@example.edu",
                "name": "Alex Instructor",
            }
        )
        assert microsoft_identity
        assert esense.microsoft_identity_from_claims(
            {
                "tid": "another-tenant",
                "oid": "wrong-tenant",
                "preferred_username": "instructor@example.edu",
            }
        ) is None
        assert esense.microsoft_identity_from_claims(
            {
                "tid": "tenant-test",
                "oid": "wrong-domain",
                "preferred_username": "outsider@example.test",
            }
        ) is None
        microsoft_user_id = esense.upsert_user_identity(
            "microsoft",
            microsoft_identity["subject"],
            microsoft_identity["email"],
            microsoft_identity["name"],
        )
        google_user_id = esense.upsert_user_identity(
            "google",
            "instructor-google-subject",
            "instructor@example.edu",
            "Alex Instructor",
        )
        assert microsoft_user_id == google_user_id
        with esense.db() as connection:
            identity_count = connection.execute(
                "SELECT count(*) FROM user_identities WHERE user_id = ?",
                (microsoft_user_id,),
            ).fetchone()[0]
        assert identity_count == 2

        def client_for(key: str):
            client = esense.app.test_client()
            with client.session_transaction() as session:
                session["user_id"] = users[key][0]
                session["csrf"] = f"csrf-{key}"
            return client

        def headers(key: str):
            return {"X-CSRF-Token": f"csrf-{key}"}

        provider = client_for("provider")
        application_page = provider.get("/")
        assert application_page.status_code == 200
        application_text = application_page.get_data(as_text=True)
        assert "data-language-select" in application_text
        assert "/static/app.js?v=39" in application_text
        assert "/static/app.css?v=32" in application_text
        assert application_text.index('id="settingsButton"') < application_text.index('id="syncState"') < application_text.index('class="logout-link"')
        assert "/static/i18n.js?v=22" in application_text
        assert 'id="documentSortFilter"' in application_text
        assert "documentation-demo-link" not in application_text
        assert "Utstedte pakker forblir private" not in application_text
        assert "Inviter person" in application_text
        assert 'id="sidebarAssignments"' in application_text
        assert "Ansvar, anleggseier og lokale instrukser" in application_text
        assert 'id="createOrganizationTopButton"' in application_text
        assert 'id="customerInput"' in application_text
        assert 'id="assigneesInput"' in application_text
        assert 'id="assignmentTeamOptions"' in application_text
        assert 'id="professionalResponsibleInput"' in application_text
        assert 'id="assigneesInput" required' not in application_text
        assert 'data-filter="available"' in application_text
        assert 'id="lateAssignmentDialog"' in application_text
        assert 'id="newCustomerFields"' in application_text
        assert 'id="executionContext"' not in application_text
        assert 'id="reviewersInput"' not in application_text
        assert 'id="desiredResultInput"' not in application_text
        assert 'id="expectedSubmissionInput"' not in application_text
        assert 'id="dueAtInput"' not in application_text
        assert 'id="evidenceDialog"' in application_text
        assert 'id="evidenceTimeline"' in application_text
        assert 'id="settingsButton"' in application_text
        assert 'id="settingsView"' in application_text
        assert 'id="profileSettingsPanel"' in application_text
        assert 'id="organizationSettingsPanel"' in application_text
        assert 'id="accessSettingsPanel"' in application_text
        assert 'id="sourceSettingsTab"' in application_text
        assert 'id="sourceSettingsPanel"' in application_text
        assert 'data-view="sources"' not in application_text
        assert 'id="sourcesView"' not in application_text
        assert '<span>Arkiv</span><b id="documentCount">0</b>' in application_text
        assert '<h1 id="documentationTitle">Kunde- og oppdragsarkiv</h1>' in application_text
        assert '<h2 class="sr-only" id="organizationDocumentsTitle">Arkiv</h2>' in application_text
        assert "Pakker fra organisasjonen og pakker som er delt direkte med deg." not in application_text
        assert "Tilgjengelig dokumentasjon" not in application_text
        assert 'id="profileDialog"' not in application_text
        assert 'id="organizationSettingsDialog"' not in application_text
        assert 'id="editProfileButton"' in application_text
        assert 'id="editOrganizationButton"' in application_text
        assert 'id="memberList"' in application_text
        assert 'id="memberDetail"' in application_text
        assert 'id="documentCustomerFilter"' in application_text
        assert 'id="documentMidnightFilter"' in application_text
        assert 'id="demoShareDialog"' in application_text
        assert 'id="demoRecipientDialog"' in application_text
        assert 'id="documentationMidnightStatus"' in application_text
        assert 'id="displayNameInput"' in application_text
        assert 'id="organizationNameDisplay"' in application_text
        assert 'id="organizationSelect"' not in application_text
        assert 'data-view="members"' not in application_text
        assert "Administrer organisasjonen og følg opp oppdrag" not in application_text
        assert "Stilling eller fagrolle" in application_text
        assert 'id="topbarAssistant"' in application_text
        assert 'class="midnight-network"' in application_text
        assert 'id="inviteQrImage"' in application_text
        assert 'id="memberRoleDialog"' in application_text
        assert 'id="overviewAssistant"' not in application_text
        assert '<h1 id="overviewTitle">Oversikt</h1>' in application_text
        assert '<h1 id="assignmentsTitle">Oppdrag</h1>' in application_text
        assert '<strong>FieldSeal</strong>' in application_text
        assert '<title>FieldSeal | dokumentasjon og oppdrag</title>' in application_text
        assert "/static/app.js?v=39" in application_text
        manifest_asset = provider.get("/static/manifest.webmanifest")
        assert manifest_asset.status_code == 200
        manifest_payload = esense.json.loads(manifest_asset.get_data(as_text=True))
        assert manifest_payload["name"].startswith("FieldSeal")
        assert manifest_payload["short_name"] == "FieldSeal"
        assert "Kun oppdrag du er tildelt" not in application_text
        app_asset = provider.get("/static/app.js?v=39")
        assert app_asset.status_code == 200
        app_text = app_asset.get_data(as_text=True)
        assert "function renderSidebarAssignments()" in app_text
        assert "async function claimAssignment()" in app_text
        assert "async function assignAvailableAssignment(event)" in app_text
        assert "function renderAssignmentTeamOptions(assignment)" in app_text
        assert "professional_responsible_email: responsibleEmail" in app_text
        assert "async function saveAssignment(event)" in app_text
        assert "async function openDuplicateAssignmentDialog()" in app_text
        assert "data-duplicate-assignment" in app_text
        assert 'form.dataset.assignmentId = ""' in app_text
        assert "async function deleteAssignment()" in app_text
        assert "async function loadCustomers()" in app_text
        assert "data-open-member-dialog" in app_text
        assert 'name = (state.document_packages || []).length ? "documentation" : "emptyOrganization"' in app_text
        assert 'data-assignment-id="${escapeHtml(item.id)}"' in app_text
        assert "async function registerEvidence(event)" in app_text
        assert "function renderMemberDetail()" in app_text
        assert "async function saveOrganizationSettings(event)" in app_text
        assert "function renderDocumentation()" in app_text
        assert "function sortDocumentPackages" in app_text
        assert 'class="document-card document-row' in app_text
        assert "organization_name || activeMembership" not in app_text
        assert "function demoDocumentPackageCard(item)" in app_text
        assert "async function changeDemoAccess(recipientKey, action)" in app_text
        assert "function openDemoRecipientView(recipientKey)" in app_text
        assert "async function verifyDemoPackage()" in app_text
        assert "async function createOrganizationJoinLink(event)" in app_text
        assert "async function saveMemberRoles(event)" in app_text
        assert "function showSettingsTab(requestedTab)" in app_text
        assert "function openSettings(tab = \"profile\")" in app_text
        assert "function renderActiveRoles(roles = [], fallback = \"Medlem\")" in app_text
        assert 'class="document-job-summary"' in app_text
        assert "function documentWorkFamilies(item)" in app_text
        assert 'customer_name: tr("Demoeier (syntetisk)")' in app_text
        assert 'assignment_title: tr("Demooppdrag: installasjon av elbillader")' in app_text
        assert 'work_families: ["electro"]' in app_text
        assert 'managerView ? "Oversikt" : reviewerView ? "Til vurdering" : "Mine oppdrag"' in app_text
        assert "FieldSeal demo" in app_text
        assert "helper.dataset.nextAction" in app_text
        css_asset = provider.get("/static/app.css?v=32")
        assert css_asset.status_code == 200
        css_text = css_asset.get_data(as_text=True)
        assert ".sidebar-assignment.current" in css_text
        assert ".app-shell.without-organization .sidebar" in css_text
        assert ".sidebar-settings.active" in css_text
        assert ".settings-tabs" in css_text
        assert ".demo-recipient-row" in css_text
        assert ".document-action-button" in css_text
        assert ".document-job-group" in css_text
        assert ".document-job-summary" in css_text
        assert ".active-role-chips" in css_text
        assert ".status-badge.unassigned" in css_text
        assert ".status-badge.assigned-worker" in css_text
        assert ".source-settings-content" in css_text
        assert ".recipient-entry-flow" in css_text
        assert ".team-options" in css_text
        assert ".team-option" in css_text
        assert "/static/tooltips.js?v=2" in application_text
        assert "midnight-mark" in application_text
        tooltip_asset = provider.get("/static/tooltips.js?v=2")
        assert tooltip_asset.status_code == 200
        tooltip_text = tooltip_asset.get_data(as_text=True)
        assert "getBoundingClientRect" in tooltip_text
        assert "window.innerWidth" in tooltip_text
        assert 'closest("dialog[open]")' in tooltip_text
        created = provider.post(
            "/api/organizations",
            json={"name": "Fagskolen", "organization_type": "school"},
            headers=headers("provider"),
        )
        assert created.status_code == 201, created.get_data(as_text=True)
        organization_id = created.get_json()["organization_id"]

        profile_updated = provider.put(
            "/api/profile",
            json={
                "display_name": users["provider"][2],
                "role_title": "Faglærer",
                "primary_family": "both",
                "phone": "+47 000 00 000",
            },
            headers=headers("provider"),
        )
        assert profile_updated.status_code == 200, profile_updated.get_data(as_text=True)
        assert profile_updated.get_json()["name"] == users["provider"][2]
        assert profile_updated.get_json()["profile"]["primary_family"] == "both"

        organization_updated = provider.put(
            f"/api/organizations/{organization_id}",
            json={
                "name": "Fagskolen",
                "organization_type": "school",
                "organization_number": "999888777",
                "address": "Skoleveien 1",
                "contact_email": "post@fagskolen.example",
                "phone": "+47 111 22 333",
            },
            headers=headers("provider"),
        )
        assert organization_updated.status_code == 200, organization_updated.get_data(as_text=True)
        assert organization_updated.get_json()["organization"]["profile"]["organization_number"] == "999888777"
        provider_bootstrap = provider.get("/api/bootstrap").get_json()
        provider_membership = next(item for item in provider_bootstrap["memberships"] if item["organization_id"] == organization_id)
        assert provider_membership["organization_profile"]["address"] == "Skoleveien 1"

        join_link_created = provider.post(
            f"/api/organizations/{organization_id}/join-links",
            json={"duration_days": 7},
            headers=headers("provider"),
        )
        assert join_link_created.status_code == 201, join_link_created.get_data(as_text=True)
        join_link = join_link_created.get_json()["join_link"]
        assert join_link["qr_data_url"].startswith("data:image/svg+xml;base64,")
        join_token: <REDACTED>
        joiner = client_for("joiner")
        join_confirmation = joiner.get(f"/join/{join_token}")
        assert join_confirmation.status_code == 200
        assert "Medlemskap gir ikke automatisk tilgang" in join_confirmation.get_data(as_text=True)
        joined = joiner.post(f"/join/{join_token}", data={"csrf": "csrf-joiner"})
        assert joined.status_code == 302
        members_after_join = provider.get(f"/api/organizations/{organization_id}/members").get_json()["members"]
        joined_member = next(item for item in members_after_join if item["email"] == users["joiner"][1])
        assert joined_member["roles"] == ["member"]
        promoted = provider.put(
            f"/api/organizations/{organization_id}/members/{joined_member['id']}",
            json={"roles": ["worker"]},
            headers=headers("provider"),
        )
        assert promoted.status_code == 200, promoted.get_data(as_text=True)
        assert promoted.get_json()["roles"] == ["worker"]

        for key, roles in (("worker", ["worker"]), ("worker2", ["worker"]), ("reviewer", ["reviewer"])):
            invited = provider.post(
                f"/api/organizations/{organization_id}/members",
                json={"email": users[key][1], "roles": roles},
                headers=headers("provider"),
            )
            assert invited.status_code == 201, invited.get_data(as_text=True)
            assert invited.get_json()["roles"] == ["member"]
            directory = provider.get(f"/api/organizations/{organization_id}/members").get_json()["members"]
            membership = next(item for item in directory if item["email"] == users[key][1])
            role_update = provider.put(
                f"/api/organizations/{organization_id}/members/{membership['id']}",
                json={"roles": roles},
                headers=headers("provider"),
            )
            assert role_update.status_code == 200, role_update.get_data(as_text=True)
            assert role_update.get_json()["roles"] == roles

        worker = client_for("worker")
        forbidden_organization_update = worker.put(
            f"/api/organizations/{organization_id}",
            json={"name": "Skal ikke lagres", "organization_type": "school"},
            headers=headers("worker"),
        )
        assert forbidden_organization_update.status_code == 403

        published = provider.post(
            "/api/assignments",
            json={
                "organization_id": organization_id,
                "title": esense.DEMO_ASSIGNMENT_TITLE,
                "purpose": "Planlegg elektro- og ekomarbeid uten utforelse.",
                "known_scope": "Ny kurs og ett strukturert nettverkspunkt.",
                "known_constraints": "Eksisterende verksted skal vaere i drift.",
                "new_customer": {"name": "Jåttå videregående skole", "address": "Skoleverksted"},
                "execution_context": "training_synthetic",
                "work_families": ["electro", "ekom"],
                "assignees": [users["worker"][1]],
                "reviewers": [users["reviewer"][1]],
            },
            headers=headers("provider"),
        )
        assert published.status_code == 201, published.get_data(as_text=True)
        assignment_id = published.get_json()["assignment_id"]
        customers = provider.get(f"/api/organizations/{organization_id}/customers")
        assert customers.status_code == 200
        customer_id = customers.get_json()["customers"][0]["id"]
        assert customers.get_json()["customers"] == [{
            "id": customer_id,
            "name": "Jåttå videregående skole",
            "address": "Skoleverksted",
            "contact_name": "",
            "contact_email": "",
        }]

        premature_package = provider.post(
            f"/api/assignments/{assignment_id}/document-packages",
            json={
                "title": "For tidlig dokumentasjon",
                "property_reference": "Verksted A",
                "owner_email": users["outsider"][1],
                "summary": "Arbeidet hevdes ferdig før planen er godkjent.",
                "tests_and_results": "Ingen prøving er gjennomført.",
            },
            headers=headers("provider"),
        )
        assert premature_package.status_code == 409

        worker_bootstrap = worker.get("/api/bootstrap")
        assert worker_bootstrap.status_code == 200
        assert organization_id in {item["organization_id"] for item in worker_bootstrap.get_json()["memberships"]}
        detail = worker.get(f"/api/assignments/{assignment_id}")
        assert detail.status_code == 200
        assert "assigned_worker" in detail.get_json()["user_roles"]
        assert detail.get_json()["assignment"]["location_context"] == "Jåttå videregående skole · Skoleverksted"
        assert detail.get_json()["assignment"]["professional_responsible"] == users["worker"][2]
        assert detail.get_json()["assignment"]["due_at"] == ""
        assert detail.get_json()["assignment"]["created_at"]
        assert detail.get_json()["evidence"] == []

        updated_team = provider.put(
            f"/api/assignments/{assignment_id}/team",
            json={
                "worker_emails": [users["worker"][1], users["worker2"][1]],
                "professional_responsible_email": users["worker2"][1],
            },
            headers=headers("provider"),
        )
        assert updated_team.status_code == 200, updated_team.get_data(as_text=True)
        team_assignment = updated_team.get_json()["assignment"]
        assert {item["email"] for item in team_assignment["assigned_workers"]} == {
            users["worker"][1], users["worker2"][1]
        }
        assert team_assignment["professional_responsible_user"]["email"] == users["worker2"][1]
        assert team_assignment["professional_responsible"] == users["worker2"][2]
        invalid_team = provider.put(
            f"/api/assignments/{assignment_id}/team",
            json={
                "worker_emails": [users["worker"][1]],
                "professional_responsible_email": users["worker2"][1],
            },
            headers=headers("provider"),
        )
        assert invalid_team.status_code == 400

        worker2 = client_for("worker2")
        worker2_detail = worker2.get(f"/api/assignments/{assignment_id}")
        assert worker2_detail.status_code == 200
        assert "assigned_worker" in worker2_detail.get_json()["user_roles"]
        team_evidence_response = worker2.post(
            f"/api/assignments/{assignment_id}/evidence",
            data={
                "phase": "during",
                "evidence_type": "other",
                "title": "Kontroll fra andre tekniker",
                "note": "Registrert av et annet medlem av arbeidslaget.",
            },
            content_type="multipart/form-data",
            headers=headers("worker2"),
        )
        assert team_evidence_response.status_code == 201, team_evidence_response.get_data(as_text=True)
        team_evidence = team_evidence_response.get_json()["evidence"]
        assert team_evidence["registered_by_name"] == users["worker2"][2]

        evidence_content = b"%PDF-1.4\nSynthetic risk assessment before work\n%%EOF\n"
        registered_evidence = worker.post(
            f"/api/assignments/{assignment_id}/evidence",
            data={
                "phase": "before",
                "evidence_type": "checklist",
                "title": "Risikovurdering før oppstart",
                "note": "Registrert før arbeidet startet.",
                "file": (io.BytesIO(evidence_content), "risikovurdering.pdf"),
            },
            content_type="multipart/form-data",
            headers=headers("worker"),
        )
        assert registered_evidence.status_code == 201, registered_evidence.get_data(as_text=True)
        evidence = registered_evidence.get_json()["evidence"]
        evidence_id = evidence["id"]
        assert evidence["phase"] == "before"
        assert evidence["registered_by_name"] == users["worker"][2]
        assert evidence["registered_at"]
        assert evidence["content_sha256"] == hashlib.sha256(evidence_content).hexdigest()
        assert len(evidence["commitment"]) == 64
        assert worker.get(evidence["download_url"]).data == evidence_content
        assert client_for("outsider").get(evidence["download_url"]).status_code == 403
        assert (Path(temp) / "evidence" / assignment_id).is_dir()

        manager_directory = provider.get(f"/api/organizations/{organization_id}/members")
        assert manager_directory.status_code == 200
        manager_worker = next(item for item in manager_directory.get_json()["members"] if item["user_id"] == users["worker"][0])
        assert "user_profile_json" not in manager_worker
        assert "phone" not in manager_worker["profile"]
        assert manager_worker["can_inspect"] is True
        assert manager_worker["assignment_count"] == 1
        assert manager_worker["evidence_count"] == 1
        assert manager_worker["assignments"][0]["id"] == assignment_id
        worker_directory = worker.get(f"/api/organizations/{organization_id}/members")
        assert worker_directory.status_code == 200
        assert worker_directory.get_json()["can_inspect"] is False
        assert all(item["can_inspect"] is False and item["assignments"] == [] for item in worker_directory.get_json()["members"])

        accepted = worker.post(
            f"/api/assignments/{assignment_id}/action",
            json={"action": "accept"},
            headers=headers("worker"),
        )
        assert accepted.status_code == 200

        planning = {
            "work_description": "Separate electro and ekom work packages with a shared route interface.",
            "building_type": "naering",
            "construction_site": "yes",
            "energized_proximity": "unknown",
            "responsibility_check": "Registered and authorized organizations must be confirmed.",
            "work_method": "Survey, isolate where required, plan routes, then define tests.",
            "risk_controls": "Clarify operation, isolation, access and coordination before start.",
            "tools_materials": "Drawings, measuring equipment and product documentation.",
            "tests_and_evidence": "Electrical verification plus copper-link certification and as-built records.",
            "open_questions": "Who carries professional responsibility and when can the workshop be isolated?",
        }
        saved = worker.put(
            f"/api/assignments/{assignment_id}/draft",
            json=planning,
            headers=headers("worker"),
        )
        assert saved.status_code == 200, saved.get_data(as_text=True)
        consideration_ids = {item["id"] for item in saved.get_json()["considerations"]}
        assert {"electrical_enterprise", "ekom_authorization", "mixed_scope_boundary", "construction_site_coordination", "electrical_work_safety"}.issubset(consideration_ids)

        provider_detail = provider.get(f"/api/assignments/{assignment_id}")
        assert provider_detail.status_code == 200
        assert provider_detail.get_json()["draft"] == {}, "Provider must not see the worker's private draft"

        submitted = worker.post(
            f"/api/assignments/{assignment_id}/submit",
            json={},
            headers=headers("worker"),
        )
        assert submitted.status_code == 201, submitted.get_data(as_text=True)
        submission_id = submitted.get_json()["submission_id"]

        reviewer = client_for("reviewer")
        reviewer_bootstrap = reviewer.get("/api/bootstrap")
        assert reviewer_bootstrap.status_code == 200
        reviewer_detail = reviewer.get(f"/api/assignments/{assignment_id}")
        assert reviewer_detail.status_code == 200
        assert reviewer_detail.get_json()["draft"] == {}
        assert reviewer_detail.get_json()["submissions"][0]["snapshot"]["planning"]["work_method"] == planning["work_method"]

        reviewed = reviewer.post(
            f"/api/submissions/{submission_id}/review",
            json={"decision": "accepted", "summary": "Planen kan brukes som forberedelsesgrunnlag.", "findings": ["Faglig ansvar ma bekreftes for utforelse."]},
            headers=headers("reviewer"),
        )
        assert reviewed.status_code == 200, reviewed.get_data(as_text=True)

        final_detail = worker.get(f"/api/assignments/{assignment_id}").get_json()
        assert final_detail["assignment"]["status"] == "accepted_plan"
        assert final_detail["submissions"][0]["reviews"][0]["decision"] == "accepted"
        assert worker.post(
            f"/api/assignments/{assignment_id}/document-packages",
            json={
                "property_reference": "Verksted A",
                "owner_email": users["outsider"][1],
                "summary": "Arbeidstakeren skal ikke kunne utstede organisasjonens pakke.",
                "tests_and_results": "Kontrollert i tilgangstesten.",
            },
            headers=headers("worker"),
        ).status_code == 403

        before_completion_review = provider.post(
            f"/api/assignments/{assignment_id}/document-packages",
            json={
                "title": "For tidlig dokumentasjon",
                "property_reference": "Verksted A",
                "owner_email": users["outsider"][1],
                "purpose": "Varig dokumentasjon for eier av anlegget",
            },
            headers=headers("provider"),
        )
        assert before_completion_review.status_code == 409

        completion = {
            "work_performed": "Installed the planned workshop circuit and Cat 6A permanent link.",
            "safe_closure": "Isolation was removed after inspection; labels, covers and work area were checked.",
            "tests_and_results": "Continuity, insulation and protective-device checks passed; copper link certification passed.",
            "deviations": "No registered deviations.",
            "evidence_references": "Electrical test report TR-001; link certificate LK-001; as-built photographs set A.",
            "handover_notes": "Owner must retain the package with the installation records.",
        }
        completion_saved = worker.put(
            f"/api/assignments/{assignment_id}/completion-draft",
            json=completion,
            headers=headers("worker"),
        )
        assert completion_saved.status_code == 200, completion_saved.get_data(as_text=True)
        assert completion_saved.get_json()["status"] == "in_execution"

        private_completion = provider.get(f"/api/assignments/{assignment_id}")
        assert private_completion.status_code == 200
        assert private_completion.get_json()["completion_draft"] == {}, "Provider must not see the worker's private completion draft"

        completion_submitted = worker.post(
            f"/api/assignments/{assignment_id}/completion-submit",
            json={},
            headers=headers("worker"),
        )
        assert completion_submitted.status_code == 201, completion_submitted.get_data(as_text=True)
        completion_submission_id = completion_submitted.get_json()["completion_submission_id"]

        completion_detail = reviewer.get(f"/api/assignments/{assignment_id}")
        assert completion_detail.status_code == 200
        completion_payload = completion_detail.get_json()
        assert completion_payload["completion_draft"] == {}
        assert completion_payload["completion_submissions"][0]["snapshot"]["completion"]["safe_closure"] == completion["safe_closure"]

        completion_reviewed = reviewer.post(
            f"/api/completion-submissions/{completion_submission_id}/review",
            json={
                "decision": "accepted",
                "summary": "Execution, safe closure and final inspection are sufficiently documented.",
                "findings": ["Evidence references are present and can be handed over."],
            },
            headers=headers("reviewer"),
        )
        assert completion_reviewed.status_code == 200, completion_reviewed.get_data(as_text=True)
        completed_detail = worker.get(f"/api/assignments/{assignment_id}").get_json()
        assert completed_detail["assignment"]["status"] == "completed"
        assert completed_detail["completion_submissions"][0]["reviews"][0]["decision"] == "accepted"

        issued = provider.post(
            f"/api/assignments/{assignment_id}/document-packages",
            json={
                "title": "Dokumentasjon - verkstedkurs og nettverkspunkt",
                "property_reference": "Skoleverksted A / tavle T1",
                "owner_email": users["outsider"][1],
                "purpose": "Varig dokumentasjon for eier av anlegget",
            },
            headers=headers("provider"),
        )
        assert issued.status_code == 201, issued.get_data(as_text=True)
        document_package = issued.get_json()["document_package"]
        package_id = document_package["id"]
        assert document_package["midnight_status"] == "queued"
        assert document_package["customer_name"] == "Jåttå videregående skole"
        assert document_package["customer_address"] == "Skoleverksted"
        assert document_package["work_families"] == ["ekom", "electro"]
        assert document_package["is_demonstration"] is True
        assert len(document_package["commitment"]) == 64
        assert document_package["grants"][0]["grant_type"] == "owner"
        assert document_package["summary"] == completion["work_performed"]
        assert document_package["report"]["tests_and_results"] == completion["tests_and_results"]
        assert document_package["report"]["safe_closure"] == completion["safe_closure"]
        assert document_package["report"]["evidence_references"] == completion["evidence_references"]
        assert document_package["report"]["completion"]["work_performed"] == completion["work_performed"]
        assert document_package["report"]["completion_reviews"][0]["decision"] == "accepted"
        assert document_package["report"]["planning"]["work_method"] == planning["work_method"]
        assert len(document_package["report"]["evidence_timeline"]) == 2
        assert {item["registered_by_name"] for item in document_package["report"]["evidence_timeline"]} == {
            users["worker"][2], users["worker2"][2]
        }
        packaged_evidence = next(
            item for item in document_package["report"]["evidence_timeline"] if item["id"] == evidence_id
        )
        assert packaged_evidence["id"] == evidence_id
        assert packaged_evidence["registered_at"] == evidence["registered_at"]
        assert packaged_evidence["content_sha256"] == evidence["content_sha256"]
        assert packaged_evidence["commitment"] == evidence["commitment"]
        assert "commitment_salt" not in packaged_evidence
        manager_directory_after_package = provider.get(f"/api/organizations/{organization_id}/members").get_json()
        manager_worker_after_package = next(item for item in manager_directory_after_package["members"] if item["user_id"] == users["worker"][0])
        assert manager_worker_after_package["document_count"] == 1
        with esense.db() as connection:
            stored_package = connection.execute(
                "SELECT manifest_json, property_reference, summary, owner_email FROM document_packages WHERE id = ?",
                (package_id,),
            ).fetchone()
        assert "Skoleverksted" not in stored_package["manifest_json"]
        assert "Continuity" not in stored_package["manifest_json"]
        assert users["outsider"][1] not in stored_package["manifest_json"]
        assert esense.parse_json(stored_package["manifest_json"], {})["algorithm"] == "AES-256-GCM"
        assert stored_package["property_reference"] == "Beskyttet anleggsreferanse"
        assert stored_package["summary"] == "Beskyttet dokumentasjonspakke"
        assert stored_package["owner_email"] == "Beskyttet mottaker"

        internal = esense.app.test_client()
        assert internal.post("/api/internal/midnight/anchors/claim").status_code == 404
        worker_headers = {"Authorization": "Bearer worker-test-token"}
        claimed = internal.post("/api/internal/midnight/anchors/claim", json={}, headers=worker_headers)
        assert claimed.status_code == 200, claimed.get_data(as_text=True)
        registration_job = claimed.get_json()["job"]
        assert registration_job["operation"] == "register"
        assert registration_job["commitment"] == document_package["commitment"]
        assert set(registration_job) == {"id", "commitment", "operation", "network", "contract_address"}
        confirmed = internal.post(
            f"/api/internal/midnight/anchors/{registration_job['id']}/result",
            json={
                "status": "confirmed",
                "transaction_id": "tx_register_test",
                "block_hash": "block_register_test",
                "block_height": 42,
                "verification_method": "finalized_transaction",
            },
            headers=worker_headers,
        )
        assert confirmed.status_code == 200, confirmed.get_data(as_text=True)

        verified = provider.get(f"/api/document-packages/{package_id}/verify")
        assert verified.status_code == 200
        verification = verified.get_json()
        assert verification["integrity"]["valid"] is True
        assert verification["midnight"]["status"] == "confirmed"
        assert verification["midnight"]["transaction"]["id"] == "tx_register_test"
        assert verification["midnight"]["transaction"]["block_height"] == 42
        public_client = esense.app.test_client()
        localized_pages = {
            language: public_client.get(f"/{language}/demo-report")
            for language in ("no", "en", "pl", "lt", "lv")
        }
        assert all(page.status_code == 200 for page in localized_pages.values())
        assert public_client.get("/fr/demo-report").status_code == 404
        public_page_text = localized_pages["en"].get_data(as_text=True)
        assert 'lang="en"' in public_page_text
        assert "Issued documentation package" in public_page_text
        assert "Handover documents" in public_page_text
        assert "Proof without publishing the report" in public_page_text
        assert '<option value="pl">Polski</option>' in public_page_text
        assert '<option value="lt">Lietuvi' in public_page_text
        assert '<option value="lv">Latvie' in public_page_text
        assert "/static/midnight-demo.locales.js?v=3" in public_page_text
        assert "/static/midnight-demo.en.js?v=4" in public_page_text
        assert "FieldSeal" in public_page_text
        locale_asset = public_client.get("/static/midnight-demo.locales.js?v=3")
        assert locale_asset.status_code == 200
        locale_text = locale_asset.get_data(as_text=True)
        assert "Wydany raport z instalacji ładowarki EV" in locale_text
        assert "FieldSeal demonstration environment" in locale_text
        assert "window.fieldSealReportLocales = locales" in locale_text
        assert "window.esenseReportLocales = locales" in locale_text
        assert "Private in FieldSeal" in locale_text
        assert "Private in esense" not in locale_text
        assert "Išduota EV įkroviklio įrengimo ataskaita" in locale_text
        assert "Izdots EV lādētāja uzstādīšanas ziņojums" in locale_text
        assert "Issued EV charger installation report" in locale_text
        assert "Suncoast EV Electric LLC" in locale_text
        assert "Cat 6A" not in locale_text
        assert "home office" not in locale_text
        client_asset = public_client.get("/static/midnight-demo.en.js?v=4")
        assert client_asset.status_code == 200
        client_text = client_asset.get_data(as_text=True)
        assert "window.fieldSealReportLocales || window.esenseReportLocales || {}" in client_text
        service_worker = public_client.get("/sw.js")
        assert service_worker.status_code == 200
        service_worker_text = service_worker.get_data(as_text=True)
        assert 'const CACHE_NAME = "esense-documentation-v41"' in service_worker_text
        for asset_url in (
            "/static/i18n.js?v=22",
            "/static/app.js?v=39",
            "/static/midnight-demo.locales.js?v=3",
            "/static/midnight-demo.en.js?v=4",
        ):
            assert asset_url in service_worker_text
        assert "Open esense" not in public_page_text
        assert "Private in esense" not in public_page_text
        public_demo = esense.app.test_client().get("/api/public/midnight-demo")
        assert public_demo.status_code == 200, public_demo.get_data(as_text=True)
        public_payload = public_demo.get_json()
        assert public_payload["demonstration"] is True
        assert public_payload["receipt"]["commitment"] == document_package["commitment"]
        assert public_payload["receipt"]["integrity"]["valid"] is True
        assert public_payload["report"]["job_reference"] == "FS-EV-DEMO-2026-0717-01"
        assert public_payload["report"]["title"] == "Issued EV charger installation report"
        assert "Bradenton, Florida" in public_payload["report"]["property_reference"]
        assert "48 A Level 2 EV charger" in public_payload["report"]["summary"]
        assert len(public_payload["report"]["documents"]) == 6
        assert len(public_payload["report"]["timeline"]) == 4
        assert public_payload["midnight"]["status"] == "confirmed"
        assert public_payload["midnight"]["transaction"]["id"] == "tx_register_test"
        public_text = esense.json.dumps(public_payload)
        assert users["outsider"][1] not in public_text
        assert "Fagskolen" not in public_text
        assert "Oppdragsgiver" not in public_text
        demo_access = provider.get("/api/midnight-demo/access")
        assert demo_access.status_code == 200
        assert all(item["status"] == "not_granted" for item in demo_access.get_json()["recipients"])
        owner_demo_access = provider.post(
            "/api/midnight-demo/access/owner",
            json={},
            headers=headers("provider"),
        )
        assert owner_demo_access.status_code == 201
        owner_recipient = next(item for item in owner_demo_access.get_json()["recipients"] if item["key"] == "owner")
        assert owner_recipient["active"] is True
        assert owner_recipient["expires_at"] == ""
        contractor_demo_access = provider.post(
            "/api/midnight-demo/access/contractor",
            json={},
            headers=headers("provider"),
        )
        assert contractor_demo_access.status_code == 201
        contractor_recipient = next(item for item in contractor_demo_access.get_json()["recipients"] if item["key"] == "contractor")
        assert contractor_recipient["active"] is True
        assert contractor_recipient["expires_at"]
        outsider_demo_access = client_for("outsider").get("/api/midnight-demo/access")
        assert outsider_demo_access.status_code == 200
        assert all(item["status"] == "not_granted" for item in outsider_demo_access.get_json()["recipients"])
        revoked_demo_access = provider.post(
            "/api/midnight-demo/access/contractor/revoke",
            json={},
            headers=headers("provider"),
        )
        assert revoked_demo_access.status_code == 200
        revoked_recipient = next(item for item in revoked_demo_access.get_json()["recipients"] if item["key"] == "contractor")
        assert revoked_recipient["status"] == "revoked"
        assert provider.post("/api/midnight-demo/access/unknown", json={}, headers=headers("provider")).status_code == 404
        unchanged_demo = esense.app.test_client().get("/api/public/midnight-demo").get_json()
        assert unchanged_demo["receipt"]["commitment"] == public_payload["receipt"]["commitment"]
        assert unchanged_demo["midnight"]["transaction"]["id"] == public_payload["midnight"]["transaction"]["id"]
        assert provider.post(
            f"/api/document-packages/{package_id}/grants",
            json={
                "recipient_email": "next@example.test",
                "grant_type": "contractor",
                "purpose": "Prosjektering av en senere endring",
                "expires_at": "2020-01-01",
            },
            headers=headers("provider"),
        ).status_code == 400
        granted = provider.post(
            f"/api/document-packages/{package_id}/grants",
            json={
                "recipient_email": "next@example.test",
                "grant_type": "contractor",
                "purpose": "Prosjektering av en senere endring",
                "expires_at": "2030-01-01",
            },
            headers=headers("provider"),
        )
        assert granted.status_code == 201
        assert len(granted.get_json()["document_package"]["grants"]) == 2
        with esense.db() as connection:
            original_envelope = connection.execute("SELECT manifest_json FROM document_packages WHERE id = ?", (package_id,)).fetchone()[0]
            connection.execute("UPDATE document_packages SET manifest_json = '{}' WHERE id = ?", (package_id,))
        tampered = provider.get(f"/api/document-packages/{package_id}/verify")
        assert tampered.status_code == 200
        assert tampered.get_json()["integrity"]["valid"] is False
        with esense.db() as connection:
            connection.execute("UPDATE document_packages SET manifest_json = ? WHERE id = ?", (original_envelope, package_id))

        outsider = client_for("outsider")
        assert outsider.get(f"/api/assignments/{assignment_id}").status_code == 403
        outsider_packages = outsider.get("/api/document-packages").get_json()["document_packages"]
        assert [item["id"] for item in outsider_packages] == [package_id]
        assert outsider_packages[0]["access_scope"] == "shared"
        assert outsider_packages[0]["grants"] == []
        assert outsider_packages[0]["report"]["handover_notes"].startswith("Owner must retain")
        assert outsider.get(f"/api/document-packages/{package_id}/verify").status_code == 200
        assert outsider.get(packaged_evidence["download_url"]).data == evidence_content

        later_evidence = provider.post(
            f"/api/assignments/{assignment_id}/evidence",
            data={
                "phase": "after",
                "evidence_type": "other",
                "title": "Etterfølgende intern merknad",
                "note": "Skal først deles når en ny dokumentasjonspakke utstedes.",
                "file": (io.BytesIO(b"Internal evidence added after package issue"), "intern.txt"),
            },
            content_type="multipart/form-data",
            headers=headers("provider"),
        )
        assert later_evidence.status_code == 201
        later_url = later_evidence.get_json()["evidence"]["download_url"]
        assert later_url
        assert outsider.get(later_url).status_code == 403
        assert outsider.post(
            f"/api/document-packages/{package_id}/grants",
            json={
                "recipient_email": "next@example.test",
                "grant_type": "contractor",
                "purpose": "Ikke tillatt",
                "expires_at": "2030-01-01",
            },
            headers=headers("outsider"),
        ).status_code == 403
        assert outsider.post("/api/organizations", json={"name": "Bad", "organization_type": "school"}).status_code == 403

        owner_grant_id = document_package["grants"][0]["id"]
        revoked_grant = provider.post(
            f"/api/document-packages/{package_id}/grants/{owner_grant_id}/revoke",
            json={},
            headers=headers("provider"),
        )
        assert revoked_grant.status_code == 200
        assert outsider.get("/api/document-packages").get_json()["document_packages"] == []
        assert outsider.get(f"/api/document-packages/{package_id}/verify").status_code == 403

        restored_owner = provider.post(
            f"/api/document-packages/{package_id}/grants",
            json={
                "recipient_email": users["outsider"][1],
                "grant_type": "owner",
                "purpose": "Varig dokumentasjon for eier av anlegget",
                "expires_at": "",
            },
            headers=headers("provider"),
        )
        assert restored_owner.status_code == 201
        assert outsider.get(f"/api/document-packages/{package_id}/verify").status_code == 200
        revoked_package = provider.post(
            f"/api/document-packages/{package_id}/revoke",
            json={"reason": "Erstattet av korrigert dokumentasjon"},
            headers=headers("provider"),
        )
        assert revoked_package.status_code == 200
        assert outsider.get("/api/document-packages").get_json()["document_packages"] == []
        assert outsider.get(f"/api/document-packages/{package_id}/verify").status_code == 403
        provider_verification = provider.get(f"/api/document-packages/{package_id}/verify")
        assert provider_verification.status_code == 200
        assert provider_verification.get_json()["status"] == "revoked"
        assert provider_verification.get_json()["midnight"]["status"] == "revocation_queued"

        revocation_claim = internal.post("/api/internal/midnight/anchors/claim", json={}, headers=worker_headers)
        assert revocation_claim.status_code == 200
        revocation_job = revocation_claim.get_json()["job"]
        assert revocation_job["operation"] == "revoke"
        assert revocation_job["commitment"] == document_package["commitment"]
        revocation_confirmed = internal.post(
            f"/api/internal/midnight/anchors/{revocation_job['id']}/result",
            json={
                "status": "confirmed",
                "transaction_id": "tx_revoke_test",
                "block_hash": "block_revoke_test",
                "block_height": 43,
                "verification_method": "finalized_transaction",
            },
            headers=worker_headers,
        )
        assert revocation_confirmed.status_code == 200
        final_verification = provider.get(f"/api/document-packages/{package_id}/verify").get_json()
        assert final_verification["midnight"]["status"] == "revoked"
        assert final_verification["midnight"]["transaction"]["id"] == "tx_register_test"
        assert final_verification["midnight"]["revocation_transaction"]["id"] == "tx_revoke_test"

        available_payload = {
            "organization_id": organization_id,
            "title": "Ledig utskifting av lysarmatur",
            "purpose": "Planlegg og dokumenter utskifting av lysarmatur.",
            "known_scope": "Tre armaturer i undervisningsrom.",
            "known_constraints": "Rommet er i bruk på dagtid.",
            "customer_id": customer_id,
            "work_families": ["electro"],
            "assignees": [],
        }
        available_created = provider.post("/api/assignments", json=available_payload, headers=headers("provider"))
        assert available_created.status_code == 201, available_created.get_data(as_text=True)
        available_id = available_created.get_json()["assignment_id"]
        provider_available = next(item for item in provider.get("/api/bootstrap").get_json()["assignments"] if item["id"] == available_id)
        assert provider_available["is_available"] is True
        assert provider_available["assigned_worker"] is None
        assert provider.get(f"/api/assignments/{available_id}").get_json()["assignment"]["professional_responsible"] == ""
        assert outsider.get(f"/api/assignments/{available_id}").status_code == 403
        assert reviewer.get(f"/api/assignments/{available_id}").status_code == 403

        updated_available_payload = {
            **available_payload,
            "title": "Ledig utskifting av LED-armatur",
            "purpose": "Skift armaturene og dokumenter sluttkontrollen.",
            "known_scope": "Tre LED-armaturer i undervisningsrom.",
        }
        assert outsider.put(
            f"/api/assignments/{available_id}",
            json=updated_available_payload,
            headers=headers("outsider"),
        ).status_code == 403
        updated_available = provider.put(
            f"/api/assignments/{available_id}",
            json=updated_available_payload,
            headers=headers("provider"),
        )
        assert updated_available.status_code == 200, updated_available.get_data(as_text=True)
        assert updated_available.get_json()["version"] == 2
        updated_detail = provider.get(f"/api/assignments/{available_id}").get_json()["assignment"]
        assert updated_detail["title"] == "Ledig utskifting av LED-armatur"
        assert updated_detail["purpose"] == "Skift armaturene og dokumenter sluttkontrollen."
        assert updated_detail["known_scope"] == "Tre LED-armaturer i undervisningsrom."
        assert updated_detail["version"] == 2

        disposable_payload = {**available_payload, "title": "Midlertidig ledig oppdrag"}
        disposable_created = provider.post("/api/assignments", json=disposable_payload, headers=headers("provider"))
        assert disposable_created.status_code == 201
        disposable_id = disposable_created.get_json()["assignment_id"]
        deleted = provider.delete(f"/api/assignments/{disposable_id}", headers=headers("provider"))
        assert deleted.status_code == 200, deleted.get_data(as_text=True)
        assert deleted.get_json()["deleted"] is True
        assert provider.get(f"/api/assignments/{disposable_id}").get_json()["assignment"]["status"] == "cancelled"
        assert provider.delete(f"/api/assignments/{disposable_id}", headers=headers("provider")).status_code == 409

        worker2 = client_for("worker2")
        worker2_bootstrap = worker2.get("/api/bootstrap")
        assert worker2_bootstrap.status_code == 200
        assert any(item["id"] == available_id and item["is_available"] for item in worker2_bootstrap.get_json()["assignments"])
        claimed = worker2.post(f"/api/assignments/{available_id}/claim", json={}, headers=headers("worker2"))
        assert claimed.status_code == 200, claimed.get_data(as_text=True)
        claimed_detail = worker2.get(f"/api/assignments/{available_id}").get_json()
        assert claimed_detail["assignment"]["status"] == "accepted"
        assert claimed_detail["assignment"]["is_available"] is False
        assert claimed_detail["assignment"]["professional_responsible"] == users["worker2"][2]
        assert "assigned_worker" in claimed_detail["user_roles"]
        assert worker.post(f"/api/assignments/{available_id}/claim", json={}, headers=headers("worker")).status_code == 409
        assert provider.put(
            f"/api/assignments/{available_id}",
            json=updated_available_payload,
            headers=headers("provider"),
        ).status_code == 409
        assert provider.delete(f"/api/assignments/{available_id}", headers=headers("provider")).status_code == 409

        later_payload = {**available_payload, "title": "Ledig kontroll av tavlemerking"}
        later_created = provider.post("/api/assignments", json=later_payload, headers=headers("provider"))
        assert later_created.status_code == 201
        later_id = later_created.get_json()["assignment_id"]
        assigned_later = provider.post(
            f"/api/assignments/{later_id}/assign",
            json={"assignee_email": users["worker"][1]},
            headers=headers("provider"),
        )
        assert assigned_later.status_code == 200, assigned_later.get_data(as_text=True)
        later_detail = worker.get(f"/api/assignments/{later_id}").get_json()
        assert later_detail["assignment"]["status"] == "published"
        assert later_detail["assignment"]["is_available"] is False
        assert later_detail["assignment"]["assigned_worker"]["email"] == users["worker"][1]
        assert later_detail["assignment"]["professional_responsible"] == users["worker"][2]
        assert "assigned_worker" in later_detail["user_roles"]

        print("workflow-smoke-ok")


if __name__ == "__main__":
    main()
