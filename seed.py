from app import app
from models import db, Expense, Category


with app.app_context():
    print ('Deleting data...')
    
    # db.session.query(expenses_categories).delete()
    db.session.commit()
    Expense.query.delete()
    Category.query.delete()
    db.session.commit()
    

    print("Creating data..")

    e1 = Expense(expense_name= 'clothes', expense_amount = 2000, date= "12/2/1242", paymode = "mpesa", category= "Food")
    e2 = Expense(expense_name= 'ugalimatumbo', expense_amount = 2000, date= "12/2/2024", paymode = "mpesa", category= "Food")

    
    c1 = Category(category_name = "Food")
    c2 = Category(category_name = "utilities")

    
    expenses = [e1,e2]
    categories = [c1,c2]
    

    db.session.add_all(expenses)

    db.session.add_all(categories)
   
    db.session.commit()

    print("seeding done")