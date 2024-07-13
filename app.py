from config import *
from models import User,Expense, Budget, Category

class Register(Resource):
    def post(self):
        data = request.get_json()
        # current_user_id =get_jwt_identity()
        new_user = User(
            email = data.get("email"),
            name = data.get("name"),
            password = bcrypt.generate_password_hash(data.get("password")).decode('utf-8')
        )
        db.session.add(new_user)
        db.session.commit()
        return jsonify({'success':'user created successfully'})

class Login(Resource):
    def post(self):
        data = request.get_json()
        email = data['email']
        password = data['password']

        user = User.query.filter_by(email=email).first()
        if user and bcrypt.check_password_hash(user.password, password):
            access_token = create_access_token(identity=user.id)
            return {"access_token": access_token}
        return {"error":"Invalid email or password"}, 400

class Users(Resource):
    @jwt_required()
    def get(self):
        # current_user_id =get_jwt_identity()
        users = User.query.all()
        users = [user.to_dict() for user in users]
        return users
    

    
class UserByID(Resource):
    @jwt_required()
    def get(self,id):        
        user = User.query.filter_by(id=id).first()
        if user:
            user = user.to_dict()
            return user, 200
        return {"error": "User not found"}, 404
    @jwt_required()
    def patch(self, id):
        user = User.query.filter_by(id=id).first()
        data = request.get_json()
        if user:
            user.name = data.get("name")
            user.email = data.get("email")
            user.password = bcrypt.generate_password_hash(data.get("password")).decode("utf-8")
            db.session.commit()
            return jsonify({"messasge": "user updated successfully"})
        return{"error": "user not found"}, 404
    
    @jwt_required()
    def delete(self, id):
        user = User.query.filter_by(id=id).first()
        if user:
            db.session.delete(user)
            db.session.commit()
            return jsonify({"message": "user deleted successfully"})
        return {"error": "User not found"}, 404    
    
class Expenses(Resource):
    @jwt_required()  
    def get(self):
        expenses = Expense.query.all()
        expenses = [expense.to_dict() for expense in expenses]
        return expenses
    
    @jwt_required() 
    def post(self):
        data = request.get_json()
        new_expense = Expense(
            expense_name=data.get('expense_name'),
            expense_amount=data.get('expense_amount'),
            date=data.get('date'),
            paymode=data.get("paymode"),
            category=data.get("category"),
            user_id=data.get("user_id")
        )
        db.session.add(new_expense)
        db.session.commit()
        return jsonify({"success": "Expense created successfully"})
        
class ExpensesByID(Resource):
    @jwt_required() 
    def get(self, id):  
        expense = Expense.query.filter_by(id=id).first()
        if expense:
            expense = expense.to_dict()
            return expense, 200
        return {"error": "Expense not found"}, 404
    
    @jwt_required()
    def patch(self, id):
        expense = Expense.query.filter_by(id=id).first()
        if expense:
            data = request.get_json()
            expense.expense_name = data.get("expense_name")
            expense.expense_amount = data.get("expense_amount")
            expense.date = data.get("date")
            expense.paymode = data.get("paymode")
            expense.category = data.get("category")
            expense.user_id = data.get("user_id")
            db.session.commit()
            return jsonify({"message": "expense updated successfully"})
        return {"error": "Expense not found"}, 404    
    @jwt_required()
    def delete(self, id):
        expense = Expense.query.filter_by(id=id).first()
        if expense:
            db.session.delete(expense)
            db.session.commit()
            return jsonify({"message": "Expense deleted successfully"})
        return {"error": "Expense not found"}, 404

class Budgets(Resource):
    @jwt_required() 
    def get(self):
        budgets = Budget.query.all()
        budgets = [budget.to_dict() for budget in budgets]
        return budgets
    
    @jwt_required()
    def post(self):
        data = request.get_json()
        new_budget = Budget(
            amount=data.get('amount'),
            budget_name=data.get('budget_name'),
            user_id=data.get('user_id')
        )
        db.session.add(new_budget)
        db.session.commit()
        return jsonify({"success": "Budget created successfully"})    

class BudgetByID(Resource):
    @jwt_required()
    def get(self, id):
        budget = Budget.query.filter_by(id=id).first()
        if budget:
            budget = budget.to_dict()
            return budget, 200
        return {"error": "Budget not found"}, 404
        
    @jwt_required()
    def patch(self, id):
        budget = Budget.query.filter_by(id=id).first()
        if budget:
            data = request.get_json()
            budget.budget_name = data.get("budget_name")
            budget.amount = data.get("amount")
            db.session.commit()
            return jsonify({"message": "budget updated successfully"})
        return {"error": "Budget not found"}, 404
    
    @jwt_required()
    def delete(self, id):
        budget = Budget.query.filter_by(id=id).first()
        if budget:
            db.session.delete(budget)
            db.session.commit()
            return {}, 204
        return {"error": "Budget not found"}, 404
    
class Categories(Resource):
    @jwt_required() 
    def get(self):
        categories = Category.query.all()
        categories = [category.to_dict() for category in categories]
        return categories
    
    @jwt_required()
    def post(self):
        data = request.get_json()
        new_category = Category(
            category_name=data.get('category_name'),
            user_id=data.get('user_id')
        )
        db.session.add(new_category)
        db.session.commit()
        return jsonify({"success": "Category created successfully"}) 




    


    

    
        

    

 

    
api.add_resource(Register, '/register')
api.add_resource(Login, "/login")
api.add_resource( Users, '/users')
api.add_resource(UserByID, '/users/<int:id>')
api.add_resource(Expenses, '/expenses')
api.add_resource(ExpensesByID, '/expenses/<int:id>')
api.add_resource(Budgets, '/budgets')
api.add_resource(BudgetByID, '/budgets/<int:id>')
api.add_resource(Categories, '/categories')


if __name__ == "__main__":
    app.run(port=5555, debug=True)