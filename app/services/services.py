from datetime import datetime, timezone
from decimal import Decimal, InvalidOperation
from sqlalchemy import select
from sqlalchemy.orm import Session
from sqlalchemy.exc import IntegrityError
from datetime import datetime, timezone, timedelta
from app.models.models import (
    User,
    Program,
    Order,
    Payment,
    Planting,
    AuditLog,
)

from security import hash_password, verify_password
from sqlalchemy.orm import Session, joinedload

# =========================
# HELPER
# =========================

def record_activity(
    db: Session,
    action: str,
    entity: str,
    user_id: int | None = None,
    entity_id: int | None = None,
    ip_address: str | None = None,
    user_agent: str | None = None,
):
    log = AuditLog(
        user_id=user_id,
        action=action,
        entity=entity,
        entity_id=entity_id,
        ip_address=ip_address,
        user_agent=user_agent[:255] if user_agent else None,
    )

    db.add(log)


def validate_program_data(
    name,
    description,
    tree_type,
    product_type,
    trees_per_unit,
    price,
    stock,
):
    name = name.strip()
    description = description.strip()
    tree_type = tree_type.strip()

    if not name or len(name) > 150:
        raise ValueError("Nama produk tidak valid")

    if not description:
        raise ValueError("Deskripsi produk wajib diisi")

    if not tree_type or len(tree_type) > 100:
        raise ValueError("Jenis pohon tidak valid")

    if product_type not in {"single", "package"}:
        raise ValueError("Tipe produk tidak valid")

    if product_type == "single":
        trees_per_unit = 1
    elif trees_per_unit < 1 or trees_per_unit > 100000:
        raise ValueError("Jumlah pohon per produk tidak valid")

    if stock < 0 or stock > 100000000:
        raise ValueError("Stok produk tidak valid")

    try:
        price = Decimal(str(price))
    except (InvalidOperation, ValueError, TypeError):
        raise ValueError("Harga produk tidak valid")

    if not price.is_finite() or price < 0 or price > Decimal("9999999999.99"):
        raise ValueError("Harga produk tidak valid")

    return {
        "name": name,
        "description": description,
        "tree_type": tree_type,
        "product_type": product_type,
        "trees_per_unit": trees_per_unit,
        "price": price,
        "stock": stock,
    }


# =========================
# 1. AUTHENTICATION
# =========================

def register_user(
    db: Session,
    name: str,
    email: str,
    password: str,
    ip_address: str | None = None,
):
    name = name.strip()
    email = email.strip().lower()

    if not name or len(name) > 100:
        raise ValueError("Nama tidak valid")

    if not email or len(email) > 150:
        raise ValueError("Email tidak valid")

    if len(password) < 8 or len(password) > 128:
        raise ValueError("Password harus terdiri dari 8-128 karakter")

    existing_user = db.scalar(
        select(User).where(User.email == email)
    )

    if existing_user:
        raise ValueError("Email sudah terdaftar")

    user = User(
        name=name,
        email=email,
        password_hash=hash_password(password),
        role="user",
        is_active=True,
    )

    try:
        db.add(user)
        db.flush()

        record_activity(
            db,
            action="REGISTER",
            entity="users",
            user_id=user.id,
            entity_id=user.id,
            ip_address=ip_address,
        )

        db.commit()
        db.refresh(user)

        return user

    except IntegrityError:
        db.rollback()
        raise ValueError("Email sudah digunakan")

    except Exception:
        db.rollback()
        raise


def authenticate_user(
    db: Session,
    email: str,
    password: str,
    ip_address: str | None = None,
    user_agent: str | None = None,
):
    email = email.strip().lower()

    user = db.scalar(
        select(User)
        .where(User.email == email)
        .with_for_update()
    )

    # Email tidak ditemukan atau akun tidak aktif. Jangan bocorkan kondisi akun.
    if not user or not user.is_active:
        record_activity(
            db, action="LOGIN_FAILED", entity="users",
            ip_address=ip_address, user_agent=user_agent,
        )
        db.commit()
        return None, "Email atau password salah."

    now = datetime.now(timezone.utc)

    if user.locked_until:
        locked_until = user.locked_until
        if locked_until.tzinfo is None:
            locked_until = locked_until.replace(tzinfo=timezone.utc)

        if now < locked_until:
            remaining = int((locked_until - now).total_seconds() / 60) + 1
            record_activity(
                db, action="LOGIN_BLOCKED", entity="users",
                user_id=user.id, entity_id=user.id,
                ip_address=ip_address, user_agent=user_agent,
            )
            db.commit()
            return None, f"Akun terkunci. Silakan coba lagi dalam {remaining} menit."

        user.failed_login_attempts = 0
        user.locked_until = None

    if not verify_password(password, user.password_hash):
        user.failed_login_attempts += 1

        if user.failed_login_attempts >= 3:
            user.failed_login_attempts = 3
            user.locked_until = now + timedelta(minutes=15)
            action = "LOGIN_LOCKED"
            message = (
                "Terlalu banyak percobaan login yang salah. "
                "Akun dikunci selama 15 menit."
            )
        else:
            action = "LOGIN_FAILED"
            remaining_attempts = 3 - user.failed_login_attempts
            message = (
                f"Email atau password salah. "
                f"Sisa percobaan: {remaining_attempts} kali."
            )

        record_activity(
            db, action=action, entity="users",
            user_id=user.id, entity_id=user.id,
            ip_address=ip_address, user_agent=user_agent,
        )
        db.commit()
        return None, message

    user.failed_login_attempts = 0
    user.locked_until = None
    record_activity(
        db, action="LOGIN_SUCCESS", entity="users",
        user_id=user.id, entity_id=user.id,
        ip_address=ip_address, user_agent=user_agent,
    )
    db.commit()
    db.refresh(user)
    return user, None


# 2. PROGRAM / PRODUK
# =========================

def get_programs(db: Session):
    return db.scalars(
        select(Program)
        .where(Program.is_active.is_(True))
        .order_by(Program.id.desc())
    ).all()


def get_program_detail(db: Session, program_id: int):
    return db.scalar(
        select(Program).where(
            Program.id == program_id,
            Program.is_active.is_(True)
        )
    )


def get_all_programs(db: Session):
    return db.scalars(
        select(Program).order_by(Program.id.desc())
    ).all()


def create_program(
    db: Session,
    name: str,
    description: str,
    tree_type: str,
    product_type: str,
    trees_per_unit: int,
    price,
    stock: int,
    admin_id: int,
    ip_address: str | None = None,
    image_path: str | None = None,
):
    data = validate_program_data(
        name,
        description,
        tree_type,
        product_type,
        trees_per_unit,
        price,
        stock,
    )

    try:
        program = Program(
            **data,
            image_path=image_path,
            is_active=True,
        )

        db.add(program)
        db.flush()

        record_activity(
            db,
            action="CREATE_PRODUCT",
            entity="programs",
            user_id=admin_id,
            entity_id=program.id,
            ip_address=ip_address,
        )

        db.commit()
        db.refresh(program)

        return program

    except IntegrityError:
        db.rollback()
        raise ValueError("Produk gagal disimpan karena data tidak valid")

    except Exception:
        db.rollback()
        raise


def update_program(
    db: Session,
    program_id: int,
    name: str,
    description: str,
    tree_type: str,
    product_type: str,
    trees_per_unit: int,
    price,
    stock: int,
    is_active: bool,
    admin_id: int,
    ip_address: str | None = None,
    image_path: str | None = None,
):
    data = validate_program_data(
        name,
        description,
        tree_type,
        product_type,
        trees_per_unit,
        price,
        stock,
    )

    try:
        program = db.scalar(
            select(Program)
            .where(Program.id == program_id)
            .with_for_update()
        )

        if not program:
            raise ValueError("Produk tidak ditemukan")

        for field, value in data.items():
            setattr(program, field, value)

        program.is_active = is_active
        # Ganti foto hanya jika admin mengunggah foto baru
        if image_path is not None:
            program.image_path = image_path

        record_activity(
            db,
            action="UPDATE_PRODUCT",
            entity="programs",
            user_id=admin_id,
            entity_id=program.id,
            ip_address=ip_address,
        )

        db.commit()
        db.refresh(program)

        return program

    except Exception:
        db.rollback()
        raise


def deactivate_program(
    db: Session,
    program_id: int,
    admin_id: int,
    ip_address: str | None = None,
):
    try:
        program = db.scalar(
            select(Program)
            .where(Program.id == program_id)
            .with_for_update()
        )

        if not program:
            raise ValueError("Produk tidak ditemukan")

        if not program.is_active:
            raise ValueError("Produk sudah nonaktif")

        program.is_active = False

        record_activity(
            db,
            action="DEACTIVATE_PRODUCT",
            entity="programs",
            user_id=admin_id,
            entity_id=program.id,
            ip_address=ip_address,
        )

        db.commit()
        db.refresh(program)

        return program

    except Exception:
        db.rollback()
        raise


# =========================
# 3. ORDER
# =========================

def create_order(
    db: Session,
    user_id: int,
    program_id: int,
    quantity: int,
    ip_address: str | None = None,
):
    if quantity < 1 or quantity > 1000:
        raise ValueError("Jumlah bibit tidak valid")

    try:
        program = db.scalar(
            select(Program)
            .where(
                Program.id == program_id,
                Program.is_active.is_(True)
            )
            .with_for_update()
        )

        if not program:
            raise ValueError("Program tidak ditemukan")

        if program.stock < quantity:
            raise ValueError("Stok bibit tidak mencukupi")

        unit_price = Decimal(str(program.price))
        total_price = unit_price * quantity

        order = Order(
            user_id=user_id,
            program_id=program.id,
            quantity=quantity,
            unit_price=unit_price,
            total_price=total_price,
            status="pending_payment",
        )

        db.add(order)
        db.flush()

        record_activity(
            db,
            action="CREATE_ORDER",
            entity="orders",
            user_id=user_id,
            entity_id=order.id,
            ip_address=ip_address,
        )

        db.commit()
        db.refresh(order)

        return order

    except Exception:
        db.rollback()
        raise


def get_user_orders(db: Session, user_id: int):
    return db.scalars(
        select(Order)
        .where(Order.user_id == user_id)
        .order_by(Order.created_at.desc())
    ).all()


def get_order_detail(
    db: Session,
    order_id: int,
    user_id: int,
):
    return db.scalar(
        select(Order).where(
            Order.id == order_id,
            Order.user_id == user_id
        )
    )



# =========================
# 4. PAYMENT
# =========================

def create_payment(
    db: Session,
    order_id: int,
    user_id: int,
    payment_method: str,
):
    if payment_method not in {"bank_transfer", "qris"}:
        raise ValueError("Metode pembayaran tidak valid")

    try:
        order = db.scalar(
            select(Order)
            .where(
                Order.id == order_id,
                Order.user_id == user_id
            )
            .with_for_update()
        )

        if not order:
            raise ValueError("Pesanan tidak ditemukan")

        if order.status != "pending_payment":
            raise ValueError("Pesanan tidak dapat dibayar")

        payment = db.scalar(
            select(Payment)
            .where(Payment.order_id == order.id)
            .with_for_update()
        )

        if payment:
            if payment.status not in {"pending", "rejected"}:
                raise ValueError(
                    "Pembayaran sedang menunggu verifikasi atau sudah selesai"
                )

            payment.payment_method = payment_method
            payment.status = "pending"
            payment.rejection_reason = None

        else:
            payment = Payment(
                order_id=order.id,
                amount=order.total_price,
                provider="manual",
                payment_method=payment_method,
                status="pending",
            )
            db.add(payment)

        db.flush()

        record_activity(
            db,
            action="CREATE_PAYMENT",
            entity="payments",
            user_id=user_id,
            entity_id=payment.id,
        )

        db.commit()
        db.refresh(payment)

        return payment

    except Exception:
        db.rollback()
        raise


def submit_payment_proof(
    db: Session,
    order_id: int,
    user_id: int,
    proof_path: str,
):
    try:
        order = db.scalar(
            select(Order)
            .where(
                Order.id == order_id,
                Order.user_id == user_id
            )
            .with_for_update()
        )

        if not order or order.status != "pending_payment":
            raise ValueError("Pesanan tidak dapat dibayar")

        payment = db.scalar(
            select(Payment)
            .where(Payment.order_id == order_id)
            .with_for_update()
        )

        if not payment:
            raise ValueError("Data pembayaran tidak ditemukan")

        if payment.status not in {"pending", "rejected"}:
            raise ValueError("Pembayaran tidak dapat diubah")

        payment.proof_path = proof_path
        payment.status = "waiting_verification"
        payment.rejection_reason = None

        record_activity(
            db,
            action="UPLOAD_PAYMENT_PROOF",
            entity="payments",
            user_id=user_id,
            entity_id=payment.id,
        )

        db.commit()
        db.refresh(payment)

        return payment

    except Exception:
        db.rollback()
        raise


def get_user_payment(
    db: Session,
    order_id: int,
    user_id: int,
):
    return db.scalar(
        select(Payment)
        .join(Order)
        .where(
            Order.id == order_id,
            Order.user_id == user_id
        )
    )


def get_all_payments(db: Session):
    return db.scalars(
        select(Payment)
        .options(
            joinedload(Payment.order).joinedload(Order.user),
            joinedload(Payment.order).joinedload(Order.program),
        )
        .order_by(Payment.created_at.desc())
    ).all()


def get_payment_by_id(db: Session, payment_id: int):
    return db.scalar(
        select(Payment)
        .options(
            joinedload(Payment.order)
        )
        .where(Payment.id == payment_id)
    )


def approve_payment(
    db: Session,
    payment_id: int,
    admin_id: int,
):
    try:
        payment = db.scalar(
            select(Payment)
            .where(Payment.id == payment_id)
            .with_for_update()
        )

        if not payment:
            raise ValueError("Pembayaran tidak ditemukan")

        if payment.status != "waiting_verification":
            raise ValueError("Pembayaran belum siap diverifikasi")

        if not payment.proof_path:
            raise ValueError("Bukti pembayaran tidak ditemukan")

        order = db.scalar(
            select(Order)
            .where(Order.id == payment.order_id)
            .with_for_update()
        )

        if not order or order.status != "pending_payment":
            raise ValueError("Status pesanan tidak valid")

        program = db.scalar(
            select(Program)
            .where(Program.id == order.program_id)
            .with_for_update()
        )

        if not program or program.stock < order.quantity:
            raise ValueError("Stok bibit tidak mencukupi")

        if Decimal(str(payment.amount)) != Decimal(str(order.total_price)):
            raise ValueError("Nominal pembayaran tidak sesuai")

        # Stok hanya dikurangi ketika admin menyetujui pembayaran
        program.stock -= order.quantity

        now = datetime.now(timezone.utc)

        payment.status = "paid"
        payment.verified_by = admin_id
        payment.verified_at = now
        payment.paid_at = now

        order.status = "paid"

        record_activity(
            db,
            action="PAYMENT_APPROVED",
            entity="payments",
            user_id=admin_id,
            entity_id=payment.id,
        )

        db.commit()
        db.refresh(payment)

        return payment

    except Exception:
        db.rollback()
        raise


def reject_payment(
    db: Session,
    payment_id: int,
    admin_id: int,
    rejection_reason: str,
):
    rejection_reason = rejection_reason.strip()

    if not rejection_reason or len(rejection_reason) > 500:
        raise ValueError("Alasan penolakan wajib diisi")

    try:
        payment = db.scalar(
            select(Payment)
            .where(Payment.id == payment_id)
            .with_for_update()
        )

        if not payment:
            raise ValueError("Pembayaran tidak ditemukan")

        if payment.status != "waiting_verification":
            raise ValueError("Pembayaran tidak dapat ditolak")

        payment.status = "rejected"
        payment.verified_by = admin_id
        payment.verified_at = datetime.now(timezone.utc)
        payment.rejection_reason = rejection_reason

        record_activity(
            db,
            action="PAYMENT_REJECTED",
            entity="payments",
            user_id=admin_id,
            entity_id=payment.id,
        )

        db.commit()
        db.refresh(payment)

        return payment

    except Exception:
        db.rollback()
        raise

# =========================
# 5. PLANTING
# =========================

def create_planting(
    db: Session,
    order_id: int,
    location: str,
    planted_quantity: int,
    notes: str | None = None,
    admin_id: int | None = None,
):
    try:
        order = db.scalar(
            select(Order)
            .where(
                Order.id == order_id,
                Order.status == "paid"
            )
            .with_for_update()
        )

        if not order:
            raise ValueError("Pesanan belum dibayar atau tidak ditemukan")

        location = location.strip()

        if not location or len(location) > 200:
            raise ValueError("Lokasi penanaman tidak valid")

        if planted_quantity < 0:
            raise ValueError("Jumlah penanaman tidak valid")

        existing_plantings = db.scalars(
            select(Planting).where(
                Planting.order_id == order_id
            )
        ).all()

        total_planted = sum(
            planting.planted_quantity
            for planting in existing_plantings
        )

        if total_planted + planted_quantity > order.quantity:
            raise ValueError("Jumlah penanaman melebihi jumlah pesanan")

        planting = Planting(
            order_id=order_id,
            location=location,
            planted_quantity=planted_quantity,
            status="completed" if planted_quantity > 0 else "scheduled",
            planting_date=(
                datetime.now(timezone.utc)
                if planted_quantity > 0 else None
            ),
            notes=notes,
        )

        db.add(planting)
        db.flush()

        record_activity(
            db,
            action="CREATE_PLANTING",
            entity="plantings",
            user_id=admin_id,
            entity_id=planting.id,
        )

        db.commit()
        db.refresh(planting)

        return planting

    except Exception:
        db.rollback()
        raise


# =========================
# 6. ADMIN
# =========================

def get_all_orders(db: Session):
    return db.scalars(
        select(Order)
        .options(
            joinedload(Order.user),
            joinedload(Order.program),
            joinedload(Order.payment),
        )
        .order_by(Order.created_at.desc())
    ).unique().all()


def get_all_plantings(db: Session):
    return db.scalars(
        select(Planting).order_by(Planting.created_at.desc())
    ).all()


def get_all_users(db: Session):
    return db.scalars(
        select(User).order_by(User.created_at.desc())
    ).all()
