import mongoose from "mongoose";
import mongoosePaginate from "mongoose-paginate-v2";

const productsCollection = "products";

/**
 * Schema de la coleccion products
 * contiene todos los elementos del producto.
 */
const productSchema = new mongoose.Schema({
  title: { type: String, required: true, max: 150, index: true },
  description: { type: String, required: true, max: 300 },
  code: { type: String, required: true, max: 10, unique: true, index: true },
  price: { type: Number, required: true },
  status: { type: Boolean, required: false, default: true },
  stock: { type: Number, required: true, integer: true },
  category: { type: String, required: true, max: 20, index: true },
  thumbnail: { type: Array, required: false },
});

//se le añade el plugin para el paginate
productSchema.plugin(mongoosePaginate);

const productModel = mongoose.model(productsCollection, productSchema);

export default productModel;
