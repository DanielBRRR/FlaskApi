from flask import Flask
from flask import jsonify
from flask import request

from flask_jwt_extended import create_access_token
from flask_jwt_extended import get_jwt_identity
from flask_jwt_extended import jwt_required
from flask_jwt_extended import JWTManager

from datetime import datetime

from flasgger import Swagger

import pymongo
import bcrypt

from flask_cors import CORS


app = Flask(__name__)

CORS(app, supports_credentials=True)

app.config["JWT_SECRET_KEY"] = "misuperclavedeldestinofinal"

jwt = JWTManager(app)
swagger = Swagger(app, template={
    "swagger": "2.0",
    "info": {
        "title": "API de Clínica",
        "description": "Documentación de la API para agendar citas",
        "version": "0.0.1",
    },
    "securityDefinitions": {
        "Bearer": {
            "type": "apiKey",
            "name": "Authorization",
            "in": "header",
            "description": "Añade 'Bearer <tu_token>' para autenticación"
        }
    },
    "security": [{"Bearer": []}]
})

myclient = pymongo.MongoClient("mongodb://localhost:27017/")


@app.route('/', methods=['GET'])
def hello():
    return 'Hello, World!'


@app.route('/login', methods=['POST'])
def login():
    """
    Iniciar sesión en la aplicación
    ---
    tags:
      - Autenticación
    parameters:
      - name: body
        in: body
        required: true
        schema:
          type: object
          properties:
            username:
              type: string
            password:
              type: string
          required:
            - username
            - password
    responses:
      200:
        description: Token de acceso generado correctamente
        schema:
          type: object
          properties:
            access_token:
              type: string
      401:
        description: Credenciales incorrectas
        schema:
          type: object
          properties:
            msg:
              type: string
              example: Bad username or password
    """
    mydb = myclient["Clinica"]
    mycol = mydb["usuarios"]

    data = request.get_json()
    if not data:
        return jsonify({"msg": "Bad username or password"}), 401

    username = data.get('username')
    password = data.get('password')

    if not isinstance(username, str) or not username.strip():
        return jsonify({"msg": "Bad username or password"}), 401

    if not isinstance(password, str) or not password.strip():
        return jsonify({"msg": "Bad username or password"}), 401

    user = mycol.find_one({"username": username})
    if not user:
        return jsonify({"msg": "Bad username or password"}), 401

    if bcrypt.checkpw(password.encode('utf-8'), user['password'].encode('utf-8')):
        access_token = create_access_token(identity=str(username), additional_claims={"role": user.get("role", "user")})
        return jsonify(access_token=access_token), 200
    else:
        return jsonify({"msg": "Bad username or password"}), 401

    """
    Iniciar sesión en la aplicación
    ---
    tags:
      - Autenticación
    parameters:
      - name: body
        in: body
        required: true
        schema:
          type: object
          properties:
            username:
              type: string
            password:
              type: string
    responses:
      200:
        description: Token de acceso generado correctamente
      401:
        description: Credenciales incorrectas
    """
    mydb = myclient["Clinica"]
    mycol = mydb["usuarios"]

    # Extraer datos JSON
    data = request.get_json()
    if not data:
        return jsonify({"msg": "Bad username or password"}), 401

    username = data.get('username')
    password = data.get('password')

    # Validar que username y password sean strings no vacíos
    if not isinstance(username, str) or not username.strip():
        return jsonify({"msg": "Bad username or password"}), 401

    if not isinstance(password, str) or not password.strip():
        return jsonify({"msg": "Bad username or password"}), 401

    # Buscar usuario en DB
    user = mycol.find_one({"username": username})
    if not user:
        return jsonify({"msg": "Bad username or password"}), 401

    # Verificar contraseña con bcrypt
    if bcrypt.checkpw(password.encode('utf-8'), user['password'].encode('utf-8')):
        # Forzar que identity sea string y crear token con rol
        access_token = create_access_token(identity=str(username), additional_claims={"role": user.get("role", "user")})
        return jsonify(access_token=access_token), 200
    else:
        return jsonify({"msg": "Bad username or password"}), 401


@app.route("/register", methods=['POST'])
def register():
    """
    Registrar un nuevo usuario
    ---
    tags:
      - Autenticación
    parameters:
      - name: body
        in: body
        required: true
        schema:
          type: object
          properties:
            username:
              type: string
            password:
              type: string
            name:
              type: string
            lastname:
              type: string
            email:
              type: string
            phone:
              type: string
            date:
              type: string
              format: date
              example: "25/12/2025"
              description: Fecha de nacimiento en formato DD/MM/YYYY
          required:
            - username
            - password
            - date
    responses:
      200:
        description: Usuario creado correctamente
        schema:
          type: object
          properties:
            msg:
              type: string
              example: user created
      400:
        description: Solicitud incorrecta o formato de fecha inválido
        schema:
          type: object
          properties:
            msg:
              type: string
              example: Bad request or Invalid date format
    """
    mydb = myclient["Clinica"]
    mycol = mydb["usuarios"]

    data = request.get_json()
    if not data:
        return jsonify({"msg": "Bad request"}), 400

    username = data.get('username')
    password = data.get('password')
    name = data.get('name')
    lastname = data.get('lastname')
    email = data.get('email')
    phone = data.get('phone')
    date = data.get('date')
    role = data.get('role', 'user')  # Por defecto "user"

    if not username or not password or not date:
        return jsonify({"msg": "Bad request"}), 400

    try:
        datetime.strptime(date, '%d/%m/%Y')
    except ValueError:
        return jsonify({"msg": "Invalid date format"}), 400

    hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

    user = {
        "username": username,
        "password": hashed_password,
        "name": name,
        "lastname": lastname,
        "email": email,
        "phone": phone,
        "date": date,
        "role": role
    }

    if mycol.find_one({"username": username}):
        return jsonify({"msg": "User already exists"}), 400

    mycol.insert_one(user)
    return jsonify({"msg": "user created"}), 200

    """
    Registrar un nuevo usuario
    ---
    tags:
        - Autenticación
    parameters:
        - name: body
          in: body
          required: true
          schema:
            type: object
            properties:
                username:
                    type: string
                password:
                    type: string
                name:
                    type: string
                lastname:
                    type: string
                email:
                    type: string
                phone:
                    type: string
                date:
                    type: string
                    format: date
                    example: "25/12/2025"
                    description: Fecha de nacimiento en formato DD/MM/YYYY
    responses:
        200:
            description: Usuario creado correctamente
        400:
            description: Solicitud incorrecta
    """
    mydb = myclient["Clinica"]
    mycol = mydb["usuarios"]

    username = request.json.get('username', None)
    password = request.json.get('password', None)
    name = request.json.get('name', None)
    lastname = request.json.get('lastname', None)
    email = request.json.get('email', None)
    phone = request.json.get('phone', None)
    date = request.json.get('date', None)

    try:
        date = datetime.strptime(date, '%d/%m/%Y').strftime('%d/%m/%Y')
    except ValueError:
        return jsonify({"msg": "Invalid date format"}), 400

    if username is None or password is None:
        return jsonify({"msg": "Bad request"}), 400

    hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
    password = hashed_password.decode('utf-8')

    user = {
        "username": username,
        "password": password,
        "name": name,
        "lastname": lastname,
        "email": email,
        "phone": phone,
        "date": date,
        "role": role   # <-- Aquí añadí solo este campo
    }
    x = mycol.insert_one(user)

    return jsonify({"msg": "user created"}), 200


@app.route("/centers", methods=['GET'])
@jwt_required()
def centers():
    """
    Obtiene una lista de todos los centros
    ---
    tags:
      - Centros
    security:
      - Bearer: []
    responses:
      200:
        description: Lista de centros
        schema:
          type: array
          items:
            type: object
            properties:
              name:
                type: string
                description: Nombre del centro
              address:
                type: string
                description: Dirección del centro
    """
    mydb = myclient["Clinica"]
    mycol = mydb["centros"]
    centers = mycol.find({}, {"_id": 0})
    return jsonify(list(centers)), 200



@app.route("/profile", methods=['GET'])
@jwt_required()
def profile():
    """
    Obtiene el perfil del usuario actual
    ---
    tags:
      - Perfil
    security:
      - Bearer: []
    responses:
      200:
        description: Perfil del usuario
        schema:
          type: object
          properties:
            username:
              type: string
            name:
              type: string
            lastname:
              type: string
            email:
              type: string
            phone:
              type: string
            date:
              type: string
    """
    current_user = get_jwt_identity()
    mydb = myclient["Clinica"]
    mycol = mydb["usuarios"]
    user = mycol.find_one({"username": current_user}, {"_id": 0, "password": 0})
    if not user:
        return jsonify({"msg": "User not found"}), 404
    return jsonify(user), 200



@app.route("/date/create", methods=['POST'])
@jwt_required()
def createDate():
    """
    Crea una nueva cita en la base de datos.
    ---
    tags:
      - Citas
    security:
      - Bearer: []
    parameters:
      - name: body
        in: body
        required: true
        schema:
          type: object
          properties:
            center:
              type: string
              example: "Centro de Salud Madrid Norte"
            date:
              type: string
              example: "25/12/2025 14:00:00"
              description: Fecha y hora en formato DD/MM/YYYY HH:00:00
          required:
            - center
            - date
    responses:
      200:
        description: Cita creada exitosamente
        schema:
          type: object
          properties:
            msg:
              type: string
              example: Date created successfully
      400:
        description: Error en solicitud o fecha ya reservada
        schema:
          type: object
          properties:
            msg:
              type: string
              example: Center not found / Invalid date format / Date and hour already taken
    """
    current_user = get_jwt_identity()
    mydb = myclient["Clinica"]
    mycol = mydb["citas"]
    myCenters = mydb["centros"]

    data = request.get_json()
    center = data.get('center')
    date_str = data.get('date')

    if not center or not date_str:
        return jsonify({"msg": "Bad request"}), 400

    existing_center = myCenters.find_one({"name": center})
    if not existing_center:
        return jsonify({"msg": "Center not found"}), 400

    try:
        date = datetime.strptime(date_str, '%d/%m/%Y %H:00:00')
        day = date.strftime('%d/%m/%Y')
        hour = date.strftime('%H')
    except ValueError:
        return jsonify({"msg": "Invalid date format"}), 400

    existing_date = mycol.find_one({"day": day, "hour": hour, "center": center, "cancel": {"$ne": 1}})
    if existing_date:
        return jsonify({"msg": "Date and hour already taken"}), 400

    new_date = {
        "username": current_user,
        "day": day,
        "hour": hour,
        "created_at": datetime.now().strftime('%d/%m/%Y %H:%M:%S'),
        "center": center,
        "cancel": 0
    }
    mycol.insert_one(new_date)
    return jsonify({"msg": "Date created successfully"}), 200



@app.route("/date/getByDay", methods=['POST'])
@jwt_required()
def getDateByDay():
    """
    Obtiene todas las citas para un día específico
    ---
    tags:
      - Citas
    security:
      - Bearer: []
    parameters:
      - name: body
        in: body
        required: true
        schema:
          type: object
          properties:
            day:
              type: string
              example: "25"
              description: Día del mes en formato numérico (1-31)
          required:
            - day
    responses:
      200:
        description: Lista de citas del día
        schema:
          type: array
          items:
            type: object
            properties:
              username:
                type: string
              day:
                type: string
              hour:
                type: string
              center:
                type: string
      400:
        description: Solicitud incorrecta
        schema:
          type: object
          properties:
            msg:
              type: string
    """
    data = request.get_json()
    day = data.get('day')
    if not day:
        return jsonify({"msg": "Bad request"}), 400

    try:
        day_int = int(day)
        if day_int < 1 or day_int > 31:
            return jsonify({"msg": "Bad request"}), 400
    except (ValueError, TypeError):
        return jsonify({"msg": "Bad request"}), 400

    mydb = myclient["Clinica"]
    mycol = mydb["citas"]

    dates = mycol.find({"day": {"$regex": f'^{day.zfill(2)}/'}, "cancel": 0}, {"_id": 0})
    return jsonify(list(dates)), 200


@app.route("/date/getByUser", methods=['GET'])
@jwt_required()
def getDateByUser():
    """
    Obtiene las citas del usuario logeado
    ---
    tags:
        - Citas
    summary: Obtiene las citas del usuario logeado.
    description: Esta función recupera todas las citas de un usuario autenticado que no han sido canceladas.
    responses:
        200:
            description: Una lista de citas del usuario.
            content:
                application/json:
                    schema:
                        type: array
                        items:
                            type: object
                            properties:
                                username:
                                    type: string
                                    description: Nombre de usuario.
                                date:
                                    type: string
                                    example: "25/12/2025 14:00:00"
                                    description: Fecha y hora de la cita.
                                other_fields:
                                    type: string
                                    description: Otros campos relevantes de la cita.
    """

    current_user = get_jwt_identity()
    mydb = myclient["Clinica"]
    mycol = mydb["citas"]

    dates = mycol.find({"username": current_user, "cancel": {"$ne": 1}}, {"_id": 0})
    return jsonify(format_dates(list(dates)))


from flask_jwt_extended import get_jwt

@app.route("/date/cancel", methods=['POST'])
@jwt_required()
def toggleCancelDate():
    current_user = get_jwt_identity()
    claims = get_jwt()  # Payload completo, donde está el rol

    mydb = myclient["Clinica"]
    mycol = mydb["citas"]

    data = request.get_json()
    center = data.get('center')
    date_str = data.get('date')

    if not center or not date_str:
        return jsonify({"msg": "Bad request"}), 400

    try:
        date = datetime.strptime(date_str, '%d/%m/%Y %H:00:00')
        day = date.strftime('%d/%m/%Y')
        hour = date.strftime('%H')
    except ValueError:
        return jsonify({"msg": "Invalid date format"}), 400

    # Construir filtro condicional según rol
    filter_query = {
        "day": day,
        "hour": hour,
        "center": center,
    }

    # Si no es admin, añadir filtro para solo su usuario
    if claims.get('role') != 'admin':
        filter_query["username"] = current_user

    # Buscar la cita actual para saber su estado cancel
    cita = mycol.find_one(filter_query)
    if not cita:
        return jsonify({"msg": "Date not found"}), 400

    nuevo_estado_cancel = 0 if cita.get("cancel", 0) == 1 else 1

    result = mycol.update_one(
        filter_query,
        {"$set": {"cancel": nuevo_estado_cancel}}
    )

    if result.matched_count == 0:
        return jsonify({"msg": "Date not found"}), 400

    estado_texto = "cancelada" if nuevo_estado_cancel == 1 else "reactivada"
    return jsonify({"msg": f"Cita {estado_texto} correctamente"}), 200




@app.route("/dates", methods=['GET'])
@jwt_required()
def getDates():
    """
    Obtiene las citas no canceladas del usuario actual.
    ---
    tags:
        - Citas
    responses:
        200:
            description: Una lista de citas no canceladas.
            schema:
                type: array
                items:
                    type: object
                    properties:
                        fecha:
                            type: string
                            description: La fecha de la cita.
                        hora:
                            type: string
                            description: La hora de la cita.
                        paciente:
                            type: string
                            description: El nombre del paciente.
                        doctor:
                            type: string
                            description: El nombre del doctor.
    """

    current_user = get_jwt_identity()
    mydb = myclient["Clinica"]
    mycol = mydb["citas"]

    dates = mycol.find({"cancel": {"$ne": 1}}, {"_id": 0})
   
    return jsonify(format_dates(list(dates)))

@app.route("/migracion", methods=['GET'])
def migracion():
    try:
        dblist = myclient.list_database_names()
        if "Clinica" not in dblist:
            mydb = myclient["Clinica"]
            collections = ["usuarios", "centros", "citas"]
            for collection in collections:
                mydb.create_collection(collection)
            
            # Insertar dos centros de Madrid
            mydb["centros"].insert_many([
                {"name": "Centro de Salud Madrid Norte", "address": "Calle de la Salud, 123, Madrid"},
                {"name": "Centro Médico Madrid Sur", "address": "Avenida de la Medicina, 456, Madrid"}
            ])
            
            # Insertar usuario admin con contraseña cifrada
            password_plain = "1234"
            hashed_password = bcrypt.hashpw(password_plain.encode('utf-8'), bcrypt.gensalt())

            admin_user = {
                "username": "patas",
                "name": "Santiago",
                "lastname": "Patiño",
                "email": "patas@example.com",
                "phone": "612345678",
                "date": "1980-01-01",  # mejor formato ISO
                "role": "admin",
                "password": hashed_password.decode('utf-8')
            }
            mydb["usuarios"].insert_one(admin_user)

            return jsonify({"msg": "Database, collections and admin user created"}), 200
        else:
            return jsonify({"msg": "Database already exists"}), 200

    except Exception as e:
        return jsonify({"msg": str(e)}), 500
@app.route("/currentUser", methods=["GET", "PATCH"])
@jwt_required()
def currentUser():
    current_user = get_jwt_identity()
    mydb = myclient["Clinica"]
    mycol = mydb["usuarios"]

    if request.method == "GET":
        user = mycol.find_one({"username": current_user}, {"_id": 0, "password": 0})
        if user is None:
            return jsonify({"msg": "User not found"}), 404
        if 'role' in user:
            user['role'] = user['role'].lower()
        return jsonify(user), 200

    if request.method == "PATCH":
        claims = get_jwt()  # claims para rol o permisos

        # Campos que pueden llegar
        name = request.json.get('name')
        lastname = request.json.get('lastname')
        email = request.json.get('email')
        phone = request.json.get('phone')
        date = request.json.get('date')
        role = request.json.get('role')

        newData = {}

        if name is not None:
            newData["name"] = name
        if lastname is not None:
            newData["lastname"] = lastname
        if email is not None:
            newData["email"] = email
        if phone is not None:
            newData["phone"] = phone
        if date is not None:
            try:
                date_obj = datetime.strptime(date, '%d/%m/%Y')
                newData["date"] = date_obj.strftime('%d/%m/%Y')
            except ValueError:
                return jsonify({"msg": "Invalid date format, debe ser DD/MM/YYYY"}), 400

        # Validar rol solo si es admin
        if role is not None:
            if claims.get('role', '').lower() == 'admin':
                newData["role"] = role.lower()
            else:
                return jsonify({"msg": "No tienes permisos para cambiar el rol"}), 403

        update_result = mycol.update_one(
            {"username": current_user},
            {"$set": newData}
        )

        if update_result.matched_count == 0:
            return jsonify({"msg": "User not found"}), 404

        user = mycol.find_one({"username": current_user}, {"_id": 0, "password": 0})

        if 'role' in user:
            user['role'] = user['role'].lower()

        return jsonify(user), 200


def format_dates(dates):
    result = []
    for date in dates:
        date['date'] = f"{date['day']} {date['hour']}:00:00"
        del date['day']
        del date['hour']
        result.append(date)

    result.sort(key=lambda x: datetime.strptime(x['date'], '%d/%m/%Y %H:00:00'))
    return result