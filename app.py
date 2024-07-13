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