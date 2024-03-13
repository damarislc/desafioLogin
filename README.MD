# Proyecto Backend ecommerce comision 50035

Author: Damaris Lujan Calvillo

## Rutas

El proyecto cuenta por el momento con 2 API REST, las rutas con las siguientes:

### Products routes:

1.  Obtener todos los productos.

    Parametros opcionales:

    - limit: default 10
    - page: default 1
    - category
    - status
    - sort

    ```bash
    GET http://localhost:8080/api/products/
    ```

    ![GET products](https://res.cloudinary.com/doxztm7ed/image/upload/v1708964158/Backend/Readme/1_ilruir.png)
    ![GET products](https://res.cloudinary.com/doxztm7ed/image/upload/v1708964209/Backend/Readme/2_u2zauy.png)

2.  Obtener producto por su id

    Donde el _:pid_ corresponde al id del producto

    ```bash
    GET http://localhost:8080/api/products/:pid
    ```

    ![Get products by id](https://res.cloudinary.com/doxztm7ed/image/upload/v1708964657/Backend/Readme/3_y2dbzc.png)

3.  Añadir producto

    ```bash
    POST http://localhost:8080/api/products
    ```

    el cual debe contener con un body raw JSON con el producto a añadir, por ejemplo:

    ```bash
    {
        "title": "HP Dock G5",
        "description": "Docking HP modelo G5",
        "code": "HPI123789",
        "price": 3000,
        "status": true,
        "stock": 2,
        "category": "Computadoras"
    }
    ```

    Todos los campos son obligatorios excepto "status", que por default es _true_, y "thumbnail".

    El campo "code" debe ser único.

    ![POST product](https://res.cloudinary.com/doxztm7ed/image/upload/v1708964809/Backend/Readme/4_nrpnzo.png)

4.  Actualizar producto

    ```bash
    PUT http://localhost:8080/api/products/:pid
    ```

    donde el _:pid_ corresponde al id del producto a actualizar.

    Debe contener con un body raw JSON con los campos del producto a modificar, por ejemplo:

    ```bash
    {
        "title": "HP Dock G6",
        "price": 4000
    }
    ```

    ![PUT product](https://res.cloudinary.com/doxztm7ed/image/upload/v1708965458/Backend/Readme/5_myrjty.png)

5.  Borrar producto

    ```bash
    DELETE http://localhost:8080/api/products/:pid
    ```

    donde el _:pid_ corresponde al id del producto a borrar.

    ![DELETE product](https://res.cloudinary.com/doxztm7ed/image/upload/v1708965712/Backend/Readme/6_jraycq.png)

### Cart routes:

1. Crear carrito

   ```bash
   POST http://localhost:8080/api/carts
   ```

   ![POST cart](https://res.cloudinary.com/doxztm7ed/image/upload/v1708965788/Backend/Readme/7_vjnpy0.png)

2. Añadir producto al carrito

   ```bash
   POST http://localhost:8080/api/carts/:cid/product/:pid
   ```

   donde el _:cid_ corresponde al id del carrito y _:pid_ el producto a añadir.
   ![POST product to cart](https://res.cloudinary.com/doxztm7ed/image/upload/v1708966021/Backend/Readme/8_z5cdcv.png)

3. Obtener productos del carrito

   ```bash
   GET http://localhost:8080/api/carts/:cid
   ```

   donde el _:cid_ corresponde al id del carrito.
   ![GET products from cart](https://res.cloudinary.com/doxztm7ed/image/upload/v1708966097/Backend/Readme/9_cgzrfp.png)

4. Modificar la cantidad de un producto del carrito

   ```bash
   PUT http://localhost:8080/api/carts/:cid/product/:pid
   ```

   donde el _:cid_ corresponde al id del carrito y _:pid_ el producto a modificar.

   recibe como body raw un json con la cantidad a modificar:

   ```bash
   { "quantity": 5 }
   ```

   ![PUT modify quantity of products in cart](https://res.cloudinary.com/doxztm7ed/image/upload/v1708966356/Backend/Readme/10_pypmbq.png)

5. Eliminar producto del carrito

   ```bash
   DELETE http://localhost:8080/api/carts/:cid/product/:pid
   ```

   donde el _:cid_ corresponde al id del carrito y _:pid_ el producto a eliminar.

   ![DELETE producto del carrito](https://res.cloudinary.com/doxztm7ed/image/upload/v1708966586/Backend/Readme/11_apeu8m.png)

6. Actualizar productos del carrito

   ```bash
   PUT http://localhost:8080/api/carts/:cid
   ```

   donde el _:cid_ corresponde al id del carrito.

   Recibe como body raw un arreglo con los productos a actualizar, si no existen los agrega y si ya existe solo actualiza la cantidad.

   ![PUT productos en el carrito](https://res.cloudinary.com/doxztm7ed/image/upload/v1708966743/Backend/Readme/12_ysiybs.png)

7. Eliminar todos los productos del carrito

   ```bash
    DELETE http://localhost:8080/api/carts/:cid
   ```

   donde el _:cid_ corresponde al id del carrito.

   ![DELETE todos los productos del carrito](https://res.cloudinary.com/doxztm7ed/image/upload/v1708966844/Backend/Readme/13_rwouer.png)

### Chat:

El chat se encuentra en la ruta raiz y se puede acceder desde:

```bash
http://localhost:8080/
```

Los mensajes serán almacenados en la base de datos en la colección messages y contendrá un campo user con el email del usuario y el campo message con el mensaje enviado.

## Vistas

La página cuenta con las siguientes vistas:

- Registro
- Login
- Productos
- Carrito
- Chat

Actualmente la vista del carrito está hardcodeada para un cart id en específico.

### Vista de registro

```bash
http://localhost:8080/register
```

La vista de registro cuenta con un formulario con nombre, apellido, email y contraseña. Todos los campos son obligatorios.

![Vista de registro](https://res.cloudinary.com/doxztm7ed/image/upload/v1709159230/Backend/Readme/18_caw0cx.png)

Al crear un usuario nuevo enseña un mensaje para preguntar si se quiere ir a la pagina de login o registrar otro usuario.

![Mensaje](https://res.cloudinary.com/doxztm7ed/image/upload/v1709159416/Backend/Readme/19_eriaaa.png)

### Vista de login

```bash
http://localhost:8080/login
```

La vista de login cuenta con un formulario con email y contraseña. Ademas contiene un link para ir a la pagina de registro por si deseas registrarte.

![Vista de login](https://res.cloudinary.com/doxztm7ed/image/upload/v1709159588/Backend/Readme/20_f0auew.png)

### Vista de productos

```bash
http://localhost:8080/products
```

El header de la vista de productos contiene un mensaje de bienvenida del usuario y si este es admin se añade el mensaje "Soy Admin.

![Header de productos](https://res.cloudinary.com/doxztm7ed/image/upload/v1709159707/Backend/Readme/21_dleojv.png)

Tambien cuenta con un boton para hacer logout y para ir a la vista de carrito.

![Botones header](https://res.cloudinary.com/doxztm7ed/image/upload/v1709159772/Backend/Readme/22_hslcdi.png)

La página de productos lista por defecto los 10 primeros productos.
![Listado de productos](https://res.cloudinary.com/doxztm7ed/image/upload/v1709159878/Backend/Readme/14_lnjcsu.png)

Cuenta con un páginado para ver los siguientes productos
![Paginado](https://res.cloudinary.com/doxztm7ed/image/upload/v1708967949/Backend/Readme/15_gxtmmf.png)

Al añadir un producto, sale un alert avisando que se ha añadido el producto.
![Alert](https://res.cloudinary.com/doxztm7ed/image/upload/v1708967949/Backend/Readme/16_xqjfzj.png)

### Vista de carrito

La página de carrito está hardcodeada para el carrito con el id _65dbf04b8e58e8e94a3e2844_. Esta contiene una tabla con los productos añadidos al carrito.
![Carrito](https://res.cloudinary.com/doxztm7ed/image/upload/v1708967949/Backend/Readme/17_pgoted.png)
