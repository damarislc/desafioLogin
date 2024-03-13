import messageModel from "../dao/models/message.model.js";

/**
 * Clase Message Manager para el manejo de los mensajes del chat
 */
export default class MessageManager {
  /**
   * Método para añadir los mensajes a la base de datos
   * @param {*} userEmail el email del usuario
   * @param {*} message el mensaje enviado por el usuario
   * @returns la respuesta de la base de datos
   */
  async addMessage(userEmail, message) {
    try {
      return await messageModel.create({ user: userEmail, message: message });
    } catch (error) {
      console.log("Error al guardar el mensaje en la BD.");
    }
  }

  /**
   * Método para obtener todos los mensajes de la base de datos
   * @returns los mensajes almacenados
   */
  async getMessages() {
    try {
      //Busca todos los mensajes de la colección
      return await messageModel.find();
    } catch (error) {
      console.log("Error al obtener los mensajes de la BD.");
    }
  }
}
