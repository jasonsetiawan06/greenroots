
from datetime import datetime, timezone
from decimal import Decimal

from sqlalchemy import (
    Boolean,
    CheckConstraint,
    DateTime,
    ForeignKey,
    Integer,
    Numeric,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from database import Base


def utcnow():
    return datetime.now(timezone.utc)


# =========================
# 1. USERS
# =========================

class User(Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(100), nullable=False)
    email: Mapped[str] = mapped_column(
        String(150), unique=True, index=True, nullable=False
    )
    password_hash: Mapped[str] = mapped_column(String(255), nullable=False)
    role: Mapped[str] = mapped_column(String(20), default="user", nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
        # Keamanan login
    failed_login_attempts: Mapped[int] = mapped_column(
        Integer, default=0, nullable=False
    )

    locked_until: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow
    )

    orders = relationship("Order", back_populates="user")
    audit_logs = relationship("AuditLog", back_populates="user")


# =========================
# 2. PROGRAMS / PRODUK
# =========================

class Program(Base):
    __tablename__ = "programs"

    __table_args__ = (
        CheckConstraint("price >= 0", name="check_program_price"),
        CheckConstraint("stock >= 0", name="check_program_stock"),
        CheckConstraint(
            "trees_per_unit > 0",
            name="check_program_trees_per_unit"
        ),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(150), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    tree_type: Mapped[str] = mapped_column(String(100), nullable=False)
        # Lokasi foto produk di folder static
    image_path: Mapped[str | None] = mapped_column(
        String(255),
        nullable=True
    )

    # Harga per satuan produk atau paket
    price: Mapped[Decimal] = mapped_column(Numeric(12, 2), nullable=False)

    # Stok dihitung berdasarkan unit produk/paket
    stock: Mapped[int] = mapped_column(Integer, default=0, nullable=False)

    # single = bibit satuan, package = paket pohon
    product_type: Mapped[str] = mapped_column(
        String(20), default="single", nullable=False
    )

    # Jumlah pohon dalam satu unit produk
    trees_per_unit: Mapped[int] = mapped_column(
        Integer, default=1, nullable=False
    )

    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow
    )

    orders = relationship("Order", back_populates="program")
    planting_rates = relationship(
        "PlantingRate", back_populates="program"
    )


# =========================
# 3. TARIF PENANAMAN
# =========================

class PlantingRate(Base):
    __tablename__ = "planting_rates"

    __table_args__ = (
        UniqueConstraint(
            "program_id",
            "location",
            name="uq_planting_rate_program_location"
        ),
        CheckConstraint(
            "fee_per_tree >= 0",
            name="check_planting_rate_fee"
        ),
    )

    id: Mapped[int] = mapped_column(primary_key=True)

    program_id: Mapped[int] = mapped_column(
        ForeignKey("programs.id", ondelete="RESTRICT"),
        nullable=False
    )

    location: Mapped[str] = mapped_column(String(150), nullable=False)

    # Biaya penanaman untuk setiap pohon
    fee_per_tree: Mapped[Decimal] = mapped_column(
        Numeric(12, 2), nullable=False
    )

    is_active: Mapped[bool] = mapped_column(Boolean, default=True)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow
    )

    program = relationship("Program", back_populates="planting_rates")


# =========================
# 4. ORDERS / PESANAN
# =========================

class Order(Base):
    __tablename__ = "orders"

    __table_args__ = (
        CheckConstraint("quantity > 0", name="check_order_quantity"),
        CheckConstraint("total_price >= 0", name="check_order_total"),
        CheckConstraint("service_fee >= 0", name="check_order_service_fee"),
        CheckConstraint("delivery_fee >= 0", name="check_order_delivery_fee"),
        CheckConstraint("trees_per_unit > 0", name="check_order_trees_per_unit"),
    )

    id: Mapped[int] = mapped_column(primary_key=True)

    user_id: Mapped[int] = mapped_column(
        ForeignKey("users.id", ondelete="RESTRICT"),
        nullable=False
    )

    program_id: Mapped[int] = mapped_column(
        ForeignKey("programs.id", ondelete="RESTRICT"),
        nullable=False
    )

    # Jumlah unit produk yang dibeli
    quantity: Mapped[int] = mapped_column(Integer, nullable=False)

    # Snapshot harga dan jumlah pohon ketika transaksi dibuat
    unit_price: Mapped[Decimal] = mapped_column(Numeric(12, 2), nullable=False)
    trees_per_unit: Mapped[int] = mapped_column(
        Integer, default=1, nullable=False
    )

    # greenroots = ditanam oleh GreenRoots
    # self = ditanam sendiri oleh pembeli
    planting_type: Mapped[str] = mapped_column(
        String(20), default="self", nullable=False
    )

    # courier atau pickup jika pembeli menanam sendiri
    delivery_method: Mapped[str | None] = mapped_column(
        String(20), nullable=True
    )

    delivery_address: Mapped[str | None] = mapped_column(
        Text, nullable=True
    )

    # Lokasi penanaman jika menggunakan layanan GreenRoots
    planting_location: Mapped[str | None] = mapped_column(
        String(255), nullable=True
    )

    # Biaya tambahan
    service_fee: Mapped[Decimal] = mapped_column(
        Numeric(12, 2), default=Decimal("0"), nullable=False
    )

    delivery_fee: Mapped[Decimal] = mapped_column(
        Numeric(12, 2), default=Decimal("0"), nullable=False
    )

    # Total = harga produk + biaya penanaman + biaya pengiriman
    total_price: Mapped[Decimal] = mapped_column(
        Numeric(12, 2), nullable=False
    )

    status: Mapped[str] = mapped_column(
        String(30), default="pending_payment", nullable=False
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow
    )

    user = relationship("User", back_populates="orders")
    program = relationship("Program", back_populates="orders")
    payment = relationship("Payment", back_populates="order", uselist=False)
    plantings = relationship("Planting", back_populates="order")



# =========================
# 5. PAYMENTS
# =========================

class Payment(Base):
    __tablename__ = "payments"

    id: Mapped[int] = mapped_column(primary_key=True)

    order_id: Mapped[int] = mapped_column(
        ForeignKey("orders.id", ondelete="RESTRICT"),
        unique=True,
        nullable=False
    )

    amount: Mapped[Decimal] = mapped_column(
        Numeric(12, 2),
        nullable=False
    )

    # Pembayaran manual
    provider: Mapped[str] = mapped_column(
        String(50),
        default="manual",
        nullable=False
    )

    payment_method: Mapped[str | None] = mapped_column(
        String(30),
        nullable=True
    )

    provider_transaction_id: Mapped[str | None] = mapped_column(
        String(150),
        unique=True,
        nullable=True
    )

    # pending, waiting_verification, paid, rejected
    status: Mapped[str] = mapped_column(
        String(30),
        default="pending",
        nullable=False
    )

    proof_path: Mapped[str | None] = mapped_column(
        Text,
        nullable=True
    )

    verified_by: Mapped[int | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True
    )

    verified_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True
    )

    rejection_reason: Mapped[str | None] = mapped_column(
        Text,
        nullable=True
    )

    paid_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=utcnow
    )

    order = relationship("Order", back_populates="payment")



# =========================
# 6. PLANTINGS / RIWAYAT TANAM
# =========================

class Planting(Base):
    __tablename__ = "plantings"

    id: Mapped[int] = mapped_column(primary_key=True)

    order_id: Mapped[int] = mapped_column(
        ForeignKey("orders.id", ondelete="RESTRICT"),
        nullable=False
    )

    location: Mapped[str] = mapped_column(String(200), nullable=False)

    planted_quantity: Mapped[int] = mapped_column(
        Integer, default=0, nullable=False
    )

    status: Mapped[str] = mapped_column(
        String(30), default="scheduled", nullable=False
    )

    planting_date: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    proof_url: Mapped[str | None] = mapped_column(
        String(500), nullable=True
    )

    notes: Mapped[str | None] = mapped_column(Text, nullable=True)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow
    )

    order = relationship("Order", back_populates="plantings")


# =========================
# 7. AUDIT LOGS
# =========================

class AuditLog(Base):
    __tablename__ = "audit_logs"

    id: Mapped[int] = mapped_column(primary_key=True)

    user_id: Mapped[int | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True
    )

    action: Mapped[str] = mapped_column(String(100), nullable=False)
    entity: Mapped[str] = mapped_column(String(100), nullable=False)
    entity_id: Mapped[int | None] = mapped_column(Integer, nullable=True)

    ip_address: Mapped[str | None] = mapped_column(
        String(45), nullable=True
    )

    user_agent: Mapped[str | None] = mapped_column(
        String(255), nullable=True
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow
    )

    user = relationship("User", back_populates="audit_logs")


# =========================
# 8. USER SESSIONS
# =========================

class UserSession(Base):
    __tablename__ = "user_sessions"

    id: Mapped[int] = mapped_column(primary_key=True)

    user_id: Mapped[int] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False
    )

    token_hash: Mapped[str] = mapped_column(
        String(64), unique=True, index=True, nullable=False
    )

    csrf_token: Mapped[str] = mapped_column(
        String(255), nullable=False
    )

    expires_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow
    )

    user = relationship("User")
