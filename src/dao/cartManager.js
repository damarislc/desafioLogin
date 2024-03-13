import cartModel from "./models/cart.model.js";
import productModel from "./models/product.model.js";

/**
 * Clase CartManager, se utiliza para crear y obtener los carritos en la BD.
 */
export default class CartManager {
  constructor() {}

  /**
   * Método asíncrona para crear un carrito vacío.
   * @returns el carrito creado.
   */
  async addCart() {
    try {
      //Se crea un carrito con un arreglo de productos vacio
      const cart = await cartModel.create({});
      return cart;
    } catch (error) {
      //Si hubo un error, se rechaza la promesa con el error
      console.error("Error al crear el carrito", error);
      return Promise.reject("Error al crear el carrito, " + error);
    }
  }

  /**
   * Método asincrona para obtener un carrito según su id.
   * @param {*} id del carrito
   * @returns el carrito con los productos pupulados.
   */
  async getCart(id) {
    try {
      //se busca el carrito por id y se hace un populate con la colección de products para mezclar los resultados
      const cart = await cartModel
        .findById({ _id: id })
        .populate("products.productId");

      //Si el carrito no existe, manda un error
      if (!cart) {
        console.error("El carrito no existe");
        return Promise.reject("El carrito no existe");
      }
      return cart;
    } catch (error) {
      console.error("Error al leer la base de datos.", error);
      return Promise.reject("Error al leer la base de datos, " + error);
    }
  }

  /**
   * Método asíncrono para añadir un producto a un carrito.
   * @param {*} cid el id del carrito
   * @param {*} pid el id del producto
   * @returns el carrito actualizado
   */
  async addProductToCart(cid, pid) {
    try {
      //Primero busca si el carrito existe
      const cart = await cartModel.findById(cid);
      //Despues, si el producto añadir existe
      const productExists = await productModel.findById(pid);
      //Si el carrito no existe manda un mensaje de error
      if (!cart) {
        console.error("El carrito no existe");
        return Promise.reject("El carrito no existe");
        //y si el producto no existe, manda mensaje de error
      } else if (!productExists) {
        console.error("El producto no existe");
        return Promise.reject("El producto no existe");
      }

      const products = cart.products;
      //Busca el indice del producto dentro del arreglo de products del carrito
      const productIndex = products.findIndex(
        (product) => product.productId == pid
      );

      //si no existe el indice es que el carrito no se ha añadio anteriomente
      if (productIndex === -1) {
        //se crea un nuevo producto con el id y la cantidad en 1
        const newProduct = {
          productId: pid,
          quantity: 1,
        };

        //se añade al arreglo de produtos
        products.push(newProduct);

        //y se actualiza la coleccoin de cart en donde el id corresponda al carrito a actualizar
        //y retorna el resultado de la actualización
        await cartModel.updateOne(
          { _id: cid },
          { $set: { products: products } }
        );
        return await this.getCart(cid);
      }

      //si no entro al if anterior, entonces se incrementa la cantidad del producto en el arrelgo
      products[productIndex].quantity += 1;

      //y se acuatiliza el carrito correspondiente
      await cartModel.updateOne({ _id: cid }, { $set: { products: products } });
      return await this.getCart(cid);
    } catch (error) {
      //Si hubo un error, rechaza la promesa con el mensaje de error.
      console.error("Error al añadir el carrito", error);
      return Promise.reject("Error al añadir el carrito, " + error);
    }
  }

  /**
   * Método para eliminar un producto del carrito
   * @param {*} cid el id del carrito
   * @param {*} pid el id del producto
   * @returns el carrito modificado
   */
  async deleteProductFromCart(cid, pid) {
    try {
      //Primero busca si el carrito existe
      const cart = await cartModel.findById(cid);

      //Despues, si el producto a borrar del carrito existe
      const products = cart.products;
      //Busca el indice del producto dentro del arreglo de products del carrito
      const productIndex = products.findIndex(
        (product) => product.productId == pid
      );

      //Si el carrito no existe manda un mensaje de error
      if (!cart) {
        console.error("El carrito no existe");
        return Promise.reject("El carrito no existe");
        //y si el producto no existe, manda mensaje de error
      } //si no existe el indice es que el carrito no se ha añadio
      else if (productIndex === -1) {
        console.error("El producto no existe en el carrito");
        return Promise.reject("El producto no existe en el carrito");
      }

      products.splice(productIndex, 1);
      //y se acuatiliza el carrito correspondiente
      await cartModel.updateOne({ _id: cid }, { $set: { products: products } });
      return await this.getCart(cid);
    } catch (error) {
      //Si hubo un error, rechaza la promesa con el mensaje de error.
      console.error("Error al eliminar producto del carrito", error);
      return Promise.reject("Error al eliminar producto del carrito, " + error);
    }
  }

  /**
   * Método para actualizar el carrito con los productos que se le manden.
   * @param {*} cid el id del carrito
   * @param {*} products arreglo de productos
   * @returns el carrito modificado
   */
  async updateCart(cid, products) {
    try {
      //Primero busca si el carrito existe
      const cart = await cartModel.findById(cid);
      //Si el carrito no existe manda un mensaje de error
      if (!cart) {
        console.error("El carrito no existe");
        return Promise.reject("El carrito no existe");
      }

      //por cada producto dentro del arreglo
      products.forEach((product) => {
        //se busca si el producto actual existe en el carrito
        let productIndex = cart.products.findIndex(
          (cProduct) => cProduct.productId == product.productId
        );
        //si el index es diferente de -1 es que sí existe y solo se
        //modifica el quantity del producto
        if (productIndex !== -1) {
          cart.products[productIndex].quantity = product.quantity;
        } else {
          //sino, se añade el producto al arreglo de productos del carrito
          cart.products.push(product);
        }
      });

      //se actualiza el carrito
      await cartModel.updateOne(
        { _id: cid },
        { $set: { products: cart.products } }
      );
      //retorna el carrito modificado
      return await this.getCart(cid);
    } catch (error) {
      //Si hubo un error, rechaza la promesa con el mensaje de error.
      console.error("Error al actualizar el carrito", error);
      return Promise.reject("Error al actualizar el carrito, " + error);
    }
  }

  /**
   * Método para actualizar la cantidad de un producto en el carrito
   * @param {*} cid el id del carrito
   * @param {*} pid el id del producto
   * @param {*} quantity la nueva cantidad
   * @returns el carrito modificado
   */
  async updateProductQuantity(cid, pid, quantity) {
    try {
      //Primero busca si el carrito existe
      const cart = await cartModel.findById(cid);

      //Despues, si el producto existe en el carrito
      const products = cart.products;
      //Busca el indice del producto dentro del arreglo de products del carrito
      const productIndex = products.findIndex(
        (product) => product.productId == pid
      );

      //Si el carrito no existe manda un mensaje de error
      if (!cart) {
        console.error("El carrito no existe");
        return Promise.reject("El carrito no existe");
        //y si el producto no existe, manda mensaje de error
      } //si no existe el indice es que ha añadido
      else if (productIndex === -1) {
        console.error("El producto no existe en el carrito");
        return Promise.reject("El producto no existe en el carrito");
      }

      //se modificado la cantidad del producto por la cantidad que se ha mandado
      products[productIndex].quantity = quantity;

      //y se acuatiliza el carrito correspondiente
      await cartModel.updateOne({ _id: cid }, { $set: { products: products } });
      return await this.getCart(cid);
    } catch (error) {
      //Si hubo un error, rechaza la promesa con el mensaje de error.
      console.error("Error al actualizar el carrito", error);
      return Promise.reject("Error al actualizar el carrito, " + error);
    }
  }

  /**
   * Método para borrar todos los productos del carrito
   * @param {*} cid el id del carrito
   * @returns el carrito actualizado
   */
  async deleteAllProductsFromCart(cid) {
    try {
      //Primero busca si el carrito existe
      const cart = await cartModel.findById(cid);
      //y se acuatiliza el carrito correspondiente
      await cartModel.updateOne({ _id: cid }, { $set: { products: [] } });
      return await this.getCart(cid);
    } catch (error) {
      //Si hubo un error, rechaza la promesa con el mensaje de error.
      console.error("Error al borrar los productos del carrito", error);
      return Promise.reject(
        "Error al borrar los productos del carrito, " + error
      );
    }
  }
}
