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
    
    api.add_resource(Categories, '/categories')