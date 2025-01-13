from typing import Optional

from fastapi_filter.contrib.sqlalchemy import Filter

from database import ProductOrm


class ProductFilter(Filter):
    name: Optional[str] = None
    price: Optional[int] = None
    brand: Optional[str] = None
    description: Optional[str] = None
    rating: Optional[int] = None
    class Constants(Filter.Constants):
        model = ProductOrm
        ordering_field_name = "custom_order_by"
        search_field_name = "custom_search"
        search_model_fields = ["name", "price", "brand", "description"]
