from config import *
from models import Expense


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
    


api.add_resource(Expenses, '/expenses')
api.add_resource(ExpensesByID, '/expenses/<int:id>')