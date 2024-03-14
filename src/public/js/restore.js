//obtiene el formulario
const form = document.querySelector("#restore-form");
//añade un event listener de submit al form
form.addEventListener("submit", (event) => {
  //previene el comportamiento default
  event.preventDefault();
  //obtiene los datos del form
  const data = new FormData(form);
  const obj = {};

  //introduce al objeto el contenido del form con clave - valor
  data.forEach((value, key) => (obj[key] = value));

  //hace un fetch a la api de restore con la informacion introducida por el usuario
  fetch("/api/sessions/restore", {
    method: "POST",
    body: JSON.stringify(obj),
    headers: {
      "Content-Type": "application/json",
    },
  })
    .then((res) => res.json())
    .then((result) => {
      //si es exitoso muestra un mensaje y manda a la pagina de login
      if (result.status === "success") {
        Swal.fire({
          title: "Contraseña restaurada exitosamente",
          icon: "success",
          showDenyButton: false,
          confirmButtonText: "Login",
        }).then((result) => {
          //funcoinamiento del boton login, redirige a la pagina de login
          if (result.isConfirmed) window.location.href = "/login";
        });
      } else {
        ////sino, manda un mensaje de error
        Swal.fire({
          title: "Error al registrarse",
          icon: "error",
          text: result.message,
        });
      }
    })
    .catch((error) => {
      //si algo salio mal en el fetch, mada un msj de error
      Swal.fire({
        title: "Error al registrarse",
        icon: "error",
        text: error,
      });
    });
});
