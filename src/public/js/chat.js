const socket = io();

//Event listener para el formulario del chat
document.querySelector("#chat-form").addEventListener("submit", (e) => {
  //previene el comportamiento default del submit
  e.preventDefault();
  //obtiene el elemento con el id message
  const messageInput = document.querySelector("#message");
  //obtiene el valor del elemento
  const message = messageInput.value;
  //borra el contenido del elemento
  messageInput.value = "";
  //manda el mensaje al backend
  socket.emit("chatMessage", message);
});

//Detecta el socket con el evento "message"
socket.on("message", (data) => {
  //Obtiene le elemento con el id chat-messages
  const chatMessages = document.querySelector("#chat-messages");
  //crea un elemento div
  const messageElement = document.createElement("div");
  //le añade el codigo html al elemento div con el email del usuario y el mensaje
  messageElement.innerHTML = `<strong>${data.userEmail}:</strong> ${data.message}`;
  //añade el elemento div al elemento chat-messages
  chatMessages.appendChild(messageElement);
});

//Detect el socket con el evento error
socket.on("error", (error) => {
  //Manda un alert de error si hubo un problema al almacenar el mensaje en la colección
  Swal.fire({
    title: "Error al enviar el mensaje",
    text: `Error: ${error}`,
    icon: "error",
  });
});

//Obtiene el elemento con el id useremail-form
const useremailForm = document.querySelector("#useremail-form");
//Le añade un event listener al elemento
useremailForm.addEventListener("submit", (e) => {
  //previene el comportamiento default del submit
  e.preventDefault();
  //obtiene el valor del elemento
  const userEmail = document.querySelector("#useremail").value;
  //manda el nuevo usario al backend
  socket.emit("newUser", userEmail);

  //Muestra un alert cuando el usuario se "conecta" con su email
  Swal.fire({
    title: "Bienvenido al chat",
    text: `Estas conectado como ${userEmail}`,
    icon: "success",
  });

  //oculta el form del email
  useremailForm.style.display = "none";
  //muestra el form para enviar mensajes
  document.querySelector("#chat-form").style.display = "block";
});
