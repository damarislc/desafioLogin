/**
 * Para esta entrega, se hardcodeara un cart id de
 * un carrito existente para evitar que se cree uno nuevo
 * cada que se accede a la vista de productos.
 */
const myCartId = "65dbf04b8e58e8e94a3e2844";

/**
 * Funcion para añadir un producto al carrito
 * @param {*} pid el id del producto
 */
async function addProduct(pid) {
  //se hace un fetch con el id del carrito y el id del producto
  fetch(`/api/carts/${myCartId}/product/${pid}`, {
    method: "POST",
  })
    .then((res) => res.json())
    .then((data) => {
      //si la data tiene un estatus success
      if (data.status === "success") {
        //se manda  un alert de que el producto se ha añadido al carrito
        Swal.fire({
          title: "Producto añadido al carrito",
          icon: "success",
        });
      } else {
        //sino, se manda un alert de error
        Swal.fire({
          title: "Error al añadir el producto",
          icon: "error",
        });
      }
    })
    .catch((error) => console.error(error));
}

async function gotoCart() {
  window.location.href = `/carts/${myCartId}`;
}

/**
 * Funcion para llamar a la api de logout
 */
function logout() {
  fetch("/api/sessions/logout")
    .then((res) => res.json())
    .then((result) => {
      //si salio bien redirige a la pagina de login
      if (result.status === "success") window.location.href = "/login";
    })
    .catch((error) => {
      Swal.fire({
        title: "Error al desloguearse",
        icon: "error",
        text: error,
      });
    });
}
