from fastapi import (
    FastAPI,
    Request,
    Form,
    Depends,
    HTTPException,
    UploadFile,
    File,
)
from starlette.middleware.trustedhost import TrustedHostMiddleware
from fastapi.responses import HTMLResponse, RedirectResponse, Response
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session

from database import get_db
from config import settings

from security import (
    get_current_user,
    require_admin,
    create_session,
    destroy_session,
    verify_csrf,
    create_anonymous_csrf,
    verify_anonymous_csrf,
    get_session,
)

from app.services.services import (
    register_user,
    authenticate_user,
    get_programs,
    get_all_programs,
    create_program,
    update_program,
    deactivate_program,
    create_order,
    get_order_detail,
    get_user_orders,
    get_all_orders,
    get_all_users,
    get_all_plantings,
    create_planting,
    record_activity,

    # PAYMENT
    create_payment,
    submit_payment_proof,
    get_user_payment,
    get_all_payments,
    get_payment_by_id,
    approve_payment,
    reject_payment,
)

from pathlib import Path
from uuid import uuid4

from fastapi.responses import (
    HTMLResponse,
    RedirectResponse,
    Response,
    FileResponse,
)

# =========================
# APPLICATION
# =========================

IS_PRODUCTION = settings.APP_ENV.lower() == "production"

app = FastAPI(
    title=settings.APP_NAME,
    docs_url=None if IS_PRODUCTION else "/docs",
    redoc_url=None if IS_PRODUCTION else "/redoc",
    openapi_url=None if IS_PRODUCTION else "/openapi.json",
    debug=False,
)
# =========================
# SECURITY MIDDLEWARE
# =========================

app.add_middleware(
    TrustedHostMiddleware,
    allowed_hosts=[
        "localhost",
        "127.0.0.1",
    ]
)

@app.middleware("http")
async def security_headers(request: Request, call_next):
    response = await call_next(request)

    response.headers["Content-Security-Policy"] = (
    "default-src 'self'; "
    "script-src 'self' 'unsafe-inline'; "
    "base-uri 'self'; "
    "form-action 'self'; "
    "frame-ancestors 'none'"
)

    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-Content-Type-Options"] = "nosniff"

    return response

app.mount(
    "/static",
    StaticFiles(directory="app/static"),
    name="static"
)

templates = Jinja2Templates(directory="app/templates")

# =========================
# HELPER UPLOAD FOTO PRODUK
# =========================

PROGRAM_IMAGE_DIR = Path("app/static/images")
MAX_PROGRAM_IMAGE_SIZE = 5 * 1024 * 1024


def save_program_image(upload: UploadFile | None):
    if not upload or not upload.filename:
        return None

    content = upload.file.read(MAX_PROGRAM_IMAGE_SIZE + 1)

    if not content:
        raise ValueError("File foto tidak boleh kosong")

    if len(content) > MAX_PROGRAM_IMAGE_SIZE:
        raise ValueError("Ukuran foto maksimal 5 MB")

    # Periksa tanda tangan file, bukan hanya nama atau MIME type
    if content.startswith(b"\xff\xd8\xff"):
        extension = ".jpg"

    elif content.startswith(b"\x89PNG\r\n\x1a\n"):
        extension = ".png"

    elif (
        len(content) >= 12
        and content[:4] == b"RIFF"
        and content[8:12] == b"WEBP"
    ):
        extension = ".webp"

    else:
        raise ValueError("Foto harus berformat JPG, PNG, atau WEBP")

    PROGRAM_IMAGE_DIR.mkdir(parents=True, exist_ok=True)

    filename = f"{uuid4().hex}{extension}"
    file_path = PROGRAM_IMAGE_DIR / filename

    file_path.write_bytes(content)

    return f"/static/images/{filename}"


# =========================
# HELPER
# =========================

def get_optional_user(request: Request, db: Session):
    session = get_session(request, db)

    if not session:
        return None, None

    user = session.user

    if not user or not user.is_active:
        return None, None

    return user, session.csrf_token


def render_auth_page(request: Request, error=None, status_code=200):
    cookie_response = Response()
    token = create_anonymous_csrf(cookie_response)

    response = templates.TemplateResponse(
        request=request,
        name="auth.html",
        context={
            "request": request,
            "csrf_token": token,
            "error": error,
        },
        status_code=status_code
    )

    # Salin cookie CSRF ke response halaman login
    for header, value in cookie_response.raw_headers:
        if header.lower() == b"set-cookie":
            response.raw_headers.append((header, value))

    return response


# =========================
# HOME
# =========================

@app.get("/", response_class=HTMLResponse)
def home(
    request: Request,
    db: Session = Depends(get_db)
):
    user, csrf_token = get_optional_user(request, db)

    return templates.TemplateResponse(
        request=request,
        name="index.html",
        context={
            "request": request,
            "app_name": settings.APP_NAME,
            "user": user,
            "csrf_token": csrf_token,
        }
    )


# =========================
# PROGRAMS
# =========================

@app.get("/programs", response_class=HTMLResponse)
def programs(
    request: Request,
    db: Session = Depends(get_db)
):
    user, csrf_token = get_optional_user(request, db)

    data = get_programs(db)

    return templates.TemplateResponse(
        request=request,
        name="programs.html",
        context={
            "request": request,
            "programs": data,
            "user": user,
            "csrf_token": csrf_token,
        }
    )


# =========================
# AUTH PAGE
# =========================

@app.get("/auth", response_class=HTMLResponse)
def auth_page(request: Request):
    return render_auth_page(request)


# =========================
# REGISTER
# =========================

@app.post("/register")
def register(
    request: Request,
    name: str = Form(...),
    email: str = Form(...),
    password: str = Form(...),
    csrf_token: str = Form(...),
    db: Session = Depends(get_db)
):
    verify_anonymous_csrf(request, csrf_token)

    try:
        user = register_user(
            db=db,
            name=name,
            email=email,
            password=password,
            ip_address=request.client.host if request.client else None,
        )

        response = RedirectResponse(
            url="/dashboard",
            status_code=303
        )

        create_session(response, user, db)

        response.delete_cookie(
            "greenroots_csrf",
            path="/",
            secure=settings.SESSION_HTTPS_ONLY,
            samesite="lax",
            httponly=True
        )

        return response

    except ValueError:
        return render_auth_page(
            request,
            error="Data registrasi tidak valid atau email sudah digunakan.",
            status_code=400
        )


# =========================
# LOGIN
# =========================

@app.post("/login")
def login(
    request: Request,
    email: str = Form(...),
    password: str = Form(...),
    csrf_token: str = Form(...),
    db: Session = Depends(get_db)
):
    verify_anonymous_csrf(request, csrf_token)

    user, login_error = authenticate_user(
        db=db,
        email=email,
        password=password,
        ip_address=request.client.host if request.client else None,
        user_agent=request.headers.get("user-agent"),
    )

    if not user:
        return render_auth_page(
            request,
            error=login_error,
            status_code=401
        )

    response = RedirectResponse(
        url="/admin" if user.role == "admin" else "/dashboard",
        status_code=303
    )

    create_session(response, user, db)

    response.delete_cookie(
        "greenroots_csrf",
        path="/",
        secure=settings.SESSION_HTTPS_ONLY,
        samesite="lax"
    )

    return response


# =========================
# LOGOUT
# =========================

@app.post("/logout")
def logout(
    request: Request,
    csrf_token: str = Form(...),
    db: Session = Depends(get_db),
    user=Depends(get_current_user)
):
    verify_csrf(request, csrf_token, db)

    response = RedirectResponse(
        url="/",
        status_code=303
    )

    record_activity(
        db,
        action="LOGOUT",
        entity="users",
        user_id=user.id,
        entity_id=user.id,
        ip_address=request.client.host if request.client else None,
        user_agent=request.headers.get("user-agent"),
    )
    db.commit()

    destroy_session(request, response, db)

    return response


# =========================
# USER DASHBOARD
# =========================

@app.get("/dashboard", response_class=HTMLResponse)
def dashboard(
    request: Request,
    db: Session = Depends(get_db),
    user=Depends(get_current_user)
):
    orders = get_user_orders(db, user.id)

    return templates.TemplateResponse(
        request=request,
        name="dashboard.html",
        context={
            "request": request,
            "user": user,
            "orders": orders,
            "csrf_token": request.state.csrf_token,
        }
    )



# =========================
# CREATE ORDER
# =========================

@app.post("/orders")
def order_program(
    request: Request,
    program_id: int = Form(...),
    quantity: int = Form(...),
    csrf_token: str = Form(...),
    db: Session = Depends(get_db),
    user=Depends(get_current_user)
):
    verify_csrf(request, csrf_token, db)

    try:
        order = create_order(
            db=db,
            user_id=user.id,
            program_id=program_id,
            quantity=quantity,
            ip_address=request.client.host if request.client else None,
        )

        return RedirectResponse(
            url=f"/payment/{order.id}",
            status_code=303
        )

    except ValueError as error:
        raise HTTPException(
            status_code=400,
            detail=str(error)
        )


# =========================
# PAYMENT PAGE
# =========================

@app.get("/payment/{order_id}", response_class=HTMLResponse)
def payment_page(
    order_id: int,
    request: Request,
    db: Session = Depends(get_db),
    user=Depends(get_current_user)
):
    order = get_order_detail(db, order_id, user.id)

    if not order:
        raise HTTPException(
            status_code=404,
            detail="Pesanan tidak ditemukan"
        )

    payment = get_user_payment(db, order_id, user.id)

    return templates.TemplateResponse(
        request=request,
        name="payment.html",
        context={
            "request": request,
            "user": user,
            "order": order,
            "payment": payment,
            "csrf_token": request.state.csrf_token,
        }
    )


# =========================
# SELECT PAYMENT METHOD
# =========================

@app.post("/payment/{order_id}")
def select_payment_method(
    order_id: int,
    request: Request,
    payment_method: str = Form(...),
    csrf_token: str = Form(...),
    db: Session = Depends(get_db),
    user=Depends(get_current_user)
):
    verify_csrf(request, csrf_token, db)

    try:
        create_payment(
            db=db,
            order_id=order_id,
            user_id=user.id,
            payment_method=payment_method,
        )

        return RedirectResponse(
            url=f"/payment/{order_id}",
            status_code=303
        )

    except ValueError as error:
        raise HTTPException(
            status_code=400,
            detail=str(error)
        )


# =========================
# UPLOAD PAYMENT PROOF
# =========================

@app.post("/payment/{order_id}/proof")
def upload_payment_proof(
    order_id: int,
    request: Request,
    proof: UploadFile = File(...),
    csrf_token: str = Form(...),
    db: Session = Depends(get_db),
    user=Depends(get_current_user)
):
    verify_csrf(request, csrf_token, db)

    payment = get_user_payment(db, order_id, user.id)

    if not payment:
        raise HTTPException(
            status_code=404,
            detail="Pembayaran tidak ditemukan"
        )

    content = proof.file.read(5 * 1024 * 1024 + 1)

    if not content or len(content) > 5 * 1024 * 1024:
        raise HTTPException(
            status_code=400,
            detail="Ukuran file maksimal 5 MB"
        )

    if content.startswith(b"\xff\xd8\xff"):
        extension = ".jpg"
    elif content.startswith(b"\x89PNG\r\n\x1a\n"):
        extension = ".png"
    elif content.startswith(b"%PDF-"):
        extension = ".pdf"
    else:
        raise HTTPException(
            status_code=400,
            detail="File harus JPG, PNG, atau PDF"
        )

    upload_dir = Path("private_uploads/payment_proofs")
    upload_dir.mkdir(parents=True, exist_ok=True)

    filename = f"{uuid4().hex}{extension}"
    file_path = upload_dir / filename

    try:
        file_path.write_bytes(content)

        submit_payment_proof(
            db=db,
            order_id=order_id,
            user_id=user.id,
            proof_path=str(file_path),
        )

    except ValueError as error:
        file_path.unlink(missing_ok=True)
        raise HTTPException(
            status_code=400,
            detail=str(error)
        )

    except Exception:
        file_path.unlink(missing_ok=True)
        raise

    return RedirectResponse(
        url=f"/payment/{order_id}",
        status_code=303
    )


# =========================
# VIEW PAYMENT PROOF
# =========================

@app.get("/payments/proof/{payment_id}")
def view_payment_proof(
    payment_id: int,
    db: Session = Depends(get_db),
    user=Depends(get_current_user)
):
    payment = get_payment_by_id(db, payment_id)

    if not payment or not payment.proof_path:
        raise HTTPException(
            status_code=404,
            detail="Bukti pembayaran tidak ditemukan"
        )

    if (
        payment.order.user_id != user.id
        and user.role != "admin"
    ):
        raise HTTPException(
            status_code=403,
            detail="Tidak memiliki akses"
        )

    path = Path(payment.proof_path)

    if not path.is_file():
        raise HTTPException(
            status_code=404,
            detail="File tidak ditemukan"
        )

    media_types = {
        ".jpg": "image/jpeg",
        ".png": "image/png",
        ".pdf": "application/pdf",
    }

    return FileResponse(
    path=path,
    media_type=media_types.get(path.suffix.lower()),
    headers={
        "Content-Disposition": "inline"
    }
)


# =========================
# ADMIN PAYMENT LIST
# =========================

@app.get("/admin/payments", response_class=HTMLResponse)
def admin_payments(
    request: Request,
    db: Session = Depends(get_db),
    admin=Depends(require_admin)
):
    payments = get_all_payments(db)

    return templates.TemplateResponse(
        request=request,
        name="admin_payments.html",
        context={
            "request": request,
            "admin": admin,
            "payments": payments,
            "csrf_token": request.state.csrf_token,
        }
    )


# =========================
# ADMIN APPROVE PAYMENT
# =========================

@app.post("/admin/payments/{payment_id}/approve")
def admin_approve_payment(
    payment_id: int,
    request: Request,
    csrf_token: str = Form(...),
    db: Session = Depends(get_db),
    admin=Depends(require_admin)
):
    verify_csrf(request, csrf_token, db)

    try:
        approve_payment(
            db=db,
            payment_id=payment_id,
            admin_id=admin.id,
        )

        return RedirectResponse(
            url="/admin/payments",
            status_code=303
        )

    except ValueError as error:
        raise HTTPException(
            status_code=400,
            detail=str(error)
        )


# =========================
# ADMIN REJECT PAYMENT
# =========================

@app.post("/admin/payments/{payment_id}/reject")
def admin_reject_payment(
    payment_id: int,
    request: Request,
    rejection_reason: str = Form(...),
    csrf_token: str = Form(...),
    db: Session = Depends(get_db),
    admin=Depends(require_admin)
):
    verify_csrf(request, csrf_token, db)

    try:
        reject_payment(
            db=db,
            payment_id=payment_id,
            admin_id=admin.id,
            rejection_reason=rejection_reason,
        )

        return RedirectResponse(
            url="/admin/payments",
            status_code=303
        )

    except ValueError as error:
        raise HTTPException(
            status_code=400,
            detail=str(error)
        )


# =========================
# ADMIN DASHBOARD
# =========================

@app.get("/admin", response_class=HTMLResponse)
def admin_dashboard(
    request: Request,
    db: Session = Depends(get_db),
    admin=Depends(require_admin)
):
    return templates.TemplateResponse(
        request=request,
        name="admin.html",
        context={
            "request": request,
            "user": admin,
            "admin": admin,

            "users": get_all_users(db),
            "orders": get_all_orders(db),
            "plantings": get_all_plantings(db),
            "products": get_all_programs(db),

            "csrf_token": request.state.csrf_token,
        }
    )


# =========================
# ADMIN: ADD PRODUCT
# =========================

@app.post("/admin/products")
def add_product(
    request: Request,
    name: str = Form(...),
    description: str = Form(...),
    tree_type: str = Form(...),
    product_type: str = Form(...),
    trees_per_unit: int = Form(...),
    price: str = Form(...),
    stock: int = Form(...),
    image: UploadFile | None = File(None),
    csrf_token: str = Form(...),
    db: Session = Depends(get_db),
    admin=Depends(require_admin)
):
    verify_csrf(request, csrf_token, db)

    image_path = None

    try:
        image_path = save_program_image(image)

        create_program(
            db=db,
            name=name,
            description=description,
            tree_type=tree_type,
            product_type=product_type,
            trees_per_unit=trees_per_unit,
            price=price,
            stock=stock,
            admin_id=admin.id,
            ip_address=request.client.host if request.client else None,
            image_path=image_path,
        )

        return RedirectResponse(
            url="/admin",
            status_code=303
        )

    except ValueError as error:
        if image_path:
            (Path("app") / "static" / image_path.lstrip("/static/")).unlink(
                missing_ok=True
            )

        raise HTTPException(
            status_code=400,
            detail=str(error)
        )

    except Exception:
        if image_path:
            (Path("app") / "static" / image_path.lstrip("/static/")).unlink(
                missing_ok=True
            )
        raise

# =========================
# ADMIN: UPDATE PRODUCT
# =========================

@app.post("/admin/products/{program_id}/update")
def edit_product(
    program_id: int,
    request: Request,
    name: str = Form(...),
    description: str = Form(...),
    tree_type: str = Form(...),
    product_type: str = Form(...),
    trees_per_unit: int = Form(...),
    price: str = Form(...),
    stock: int = Form(...),
    is_active: bool = Form(False),
    image: UploadFile | None = File(None),
    csrf_token: str = Form(...),
    db: Session = Depends(get_db),
    admin=Depends(require_admin)
):
    verify_csrf(request, csrf_token, db)

    image_path = None

    try:
        image_path = save_program_image(image)

        update_program(
            db=db,
            program_id=program_id,
            name=name,
            description=description,
            tree_type=tree_type,
            product_type=product_type,
            trees_per_unit=trees_per_unit,
            price=price,
            stock=stock,
            is_active=is_active,
            admin_id=admin.id,
            ip_address=request.client.host if request.client else None,
            image_path=image_path,
        )

        return RedirectResponse(
            url="/admin",
            status_code=303
        )

    except ValueError as error:
        if image_path:
            (Path("app") / "static" / image_path.lstrip("/static/")).unlink(
                missing_ok=True
            )

        raise HTTPException(
            status_code=400,
            detail=str(error)
        )

    except Exception:
        if image_path:
            (Path("app") / "static" / image_path.lstrip("/static/")).unlink(
                missing_ok=True
            )
        raise


# =========================
# ADMIN: DEACTIVATE PRODUCT
# =========================

@app.post("/admin/products/{program_id}/deactivate")
def remove_product(
    program_id: int,
    request: Request,
    csrf_token: str = Form(...),
    db: Session = Depends(get_db),
    admin=Depends(require_admin)
):
    verify_csrf(request, csrf_token, db)

    try:
        deactivate_program(
            db=db,
            program_id=program_id,
            admin_id=admin.id,
            ip_address=request.client.host if request.client else None,
        )

        return RedirectResponse(
            url="/admin",
            status_code=303
        )

    except ValueError as error:
        raise HTTPException(
            status_code=400,
            detail=str(error)
        )


# =========================
# ADMIN: PLANTING REPORT
# =========================

@app.post("/admin/plantings")
def add_planting(
    request: Request,
    order_id: int = Form(...),
    location: str = Form(...),
    planted_quantity: int = Form(...),
    notes: str = Form(""),
    csrf_token: str = Form(...),
    db: Session = Depends(get_db),
    admin=Depends(require_admin)
):
    verify_csrf(request, csrf_token, db)

    try:
        create_planting(
            db=db,
            order_id=order_id,
            location=location,
            planted_quantity=planted_quantity,
            notes=notes,
            admin_id=admin.id,
        )

        return RedirectResponse(
            url="/admin",
            status_code=303
        )

    except ValueError as error:
        raise HTTPException(
            status_code=400,
            detail=str(error)
        )
