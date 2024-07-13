from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import MetaData
from sqlalchemy.orm import validates
from sqlalchemy_serializer import SerializerMixin
from sqlalchemy.ext.associationproxy import association_proxy


metadata = MetaData(naming_convention={
    "fk": "fk_%(table_name)s_%(column_0_name)s_%(referred_table_name)s",
})

db = SQLAlchemy(metadata=metadata)

expenses_categories = db.Table(
    'expenses_categories',
    metadata,
    db.Column('expense_id', db.Integer, db.ForeignKey(
        'expense.id'), primary_key=True),
    db.Column('category_id', db.Integer, db.ForeignKey(
        'category.id'), primary_key=True)
)

class Category(db.Model, SerializerMixin):
    _tablename_ = "category"
    id = db.Column(db.Integer, primary_key=True)
    category_name = db.Column(db.String)
    # expenses = db.relationship('Expense', secondary='expenses_categories', back_populates="categories")
    # expenses = db.relationship('Expense', secondary=categories, backref=db.backref('expenses_categories', lazy='dynamic'))

    
    

    def _repr_(self):
        return f'<Category {self.id}, {self.category_name}>'

class Expense(db.Model, SerializerMixin):
    _tablename_ = 'expense'
    id = db.Column(db.Integer, primary_key = True)
    expense_name = db.Column(db.String)
    expense_amount = db.Column(db.Integer)
    date = db.Column(db.String)
    paymode=db.Column(db.String)
    category=db.Column(db.String)
    # user_id = db.Column(db.Integer, db.ForeignKey('user.id'))

    # user = db.relationship('User', back_populates='expenses')
    categories = db.relationship('Category', secondary='expenses_categories', back_populates="expenses")
    categories = association_proxy('expense_category', 'category')


    serialize_rules = ("-user",)


    @validates('expense_amount')
    def validate_amount(self, key, expense_amount):
        if expense_amount is None or expense_amount <= 0:
            raise ValueError("Amount must be a valid numeric value greater than zero")
        return expense_amount
    

    def _repr_(self):
        return f'<Expense {self.id}, {self.expense_name}>'
    
    