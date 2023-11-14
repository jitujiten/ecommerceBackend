// {
//     "email": "jsahu5425@gmail.com",
//     "password": "Jitu@9178",
//     "role": "user",
//     "addresses": [
//       {
//         "name": "Jitendra sahu",
//         "email": "jsahu5425gmail@gmail.com",
//         "phone": "560163798",
//         "street": "BANGLORE",
//         "city": "BANGLORE",
//         "state": "Odisha",
//         "pinCode": "563782"
//       },
//       {
//         "name": "Jitendra Sahu",
//         "email": "jsahu5425@gmail.com",
//         "phone": "56016379",
//         "street": "At/PO-PALSAMA BLOCK-REAMAL DIST-DEOGARH",
//         "city": "Reamal",
//         "state": "Odisha",
//         "pinCode": "768109"
//       },
//       {
//         "name": "Jitendra Sahu",
//         "email": "jsahu5425@gmail.com",
//         "phone": "56016379",
//         "street": "At/PO-PALSAMA BLOCK-REAMAL DIST-DEOGARH",
//         "city": "Reamal",
//         "state": "Odisha",
//         "pinCode": "768109"
//       }
//     ],
//     "id": 1
//   }

const mongoose = require("mongoose");
const { Schema } = mongoose;

const UserSchema = new Schema({
  email: {
    type: String,
    required: true,
    unique: true,
    validate: {
      validator: function (v) {
        return /^[\w-\.]+@([\w-]+\.)+[\w-]{2,4}$/.test(v);
      },
      message: (props) => `${props.value} is not a valid email address!`,
    },
  },
  password: { type: Buffer, required: true },
  role: { type: String, required: true, default: "user" },
  addresses: {
    type: [Schema.Types.Mixed],
  },
  name: { type: String },
  ProfileUrl: { type: String },
  orders: { type: [Schema.Types.Mixed] },
  salt:Buffer,
  resetPasswordToken:{type:String,default: " "}
});

const virtual = UserSchema.virtual("id");
virtual.get(function () {
  return this._id;
});
UserSchema.set("toJSON", {
  virtuals: true,
  versionKey: false,
  transform: function (doc, res) {
    delete res._id;
  },
});

exports.User = mongoose.model("User", UserSchema);
