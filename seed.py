from app import app
from models import db, User, Expense, Budget, Category, expenses_categories


with app.app_context():
    print ('Deleting data...')
    
    db.session.query(expenses_categories).delete()
    db.session.commit()
    User.query.delete()
    Expense.query.delete()
    Budget.query.delete()
    Category.query.delete()
    

    print("Creating data..")

    u1 = User(email = "dan@gmail.com", name= "dan", password= '12345678')
    u2 = User(email = 'example@gmail.com', name = 'example', password = "12345")

    e1 = Expense(expense_name= 'clothes', expense_amount = 2000, date= "12/2/1242", paymode = "mpesa", category= "Food")
    e2 = Expense(expense_name= 'ugalimatumbo', expense_amount = 2000, date= "12/2/2024", paymode = "mpesa", category= "Food")

    b1 = Budget(budget_name = "stima", amount= 300)
    b2 = Budget(budget_name = "rent", amount= 3000)

    c1 = Category(category_name = "Food")
    c2 = Category(category_name = "utilities")

    
    users = [u1,u2]
    expenses = [e1,e2]
    budgets = [b1, b2]
    categories = [c1,c2]
    

    db.session.add_all(users)
    db.session.add_all(expenses)
    db.session.add_all(budgets)
    db.session.add_all(categories)
   
    db.session.commit()

    print("seeding done")