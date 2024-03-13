//obtiene el formulario
const form = document.querySelector("#login-form");
//añade un event listener de submit al form
form.addEventListener("submit", (event) => {
  //previene el comportamiento default
  event.preventDefault();
  //obtiene los datos del form
  const data = new FormData(form);
  const obj = {};

  //introduce al objeto el contenido del form con clave - valor
  data.forEach((value, key) => (obj[key] = value));

  //hace un fetch a la api de login con la informacion introducida por el usuario
  fetch("/api/session/login", {
    method: "POST",
    body: JSON.stringify(obj),
    headers: {
      "Content-Type": "application/json",
    },
  })
    .then((response) => response.json())
    .then((result) => {
      //si el resultario es exitoso redirige la pagina a productos
      if (result.status === "success") window.location.href = "/products";
      else {
        //sino, manda un mensaje de error
        Swal.fire({
          title: "Error al iniciar sesion",
          icon: "error",
          text: result.message,
        });
      }
    })
    .catch((error) => {
      //si algo salio mal en el fetch, mada un msj de error
      Swal.fire({
        title: "Error al ingresar",
        icon: "error",
        text: error,
      });
    });
});
