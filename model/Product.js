const mongoose = require("mongoose");
const { Schema } = mongoose;

const ProductSchema = new Schema({
  title: { type: String, required: true,unique:true },
  description: { type: String, required: true },
  price: { type: Number, min: [0, "wrong min Price"], required: true },
  discountPercentage: {
    type: Number,
    min: [0, "wrong min discountPercentage"],
    max: [100, "wrong max discountPercentage"],
    required: true,
  },
  rating: {
    type: Number,
    min: [0, "wrong min rating"],
    max: [5, "wrong max rating"],
    required: true,
    default: 0,
  },
  stock: {
    type: Number,
    min: [1, "wrong min stock"],
    required: true,
  },
  brand: { type: String, required: true },
  category: { type: String, required: true },
  thumbnail: { type: String, required: true },
  images: { type: [String], required: true },
  deleted: { type: Boolean, default: false },
  colors:{type:[Schema.Types.Mixed]},
  sizes:{type:[Schema.Types.Mixed]}
});

const virtual = ProductSchema.virtual("id");
virtual.get(function () {
  return this._id;
});
ProductSchema.set("toJSON", {
  virtuals: true,
  versionKey: false,
  transform: function (doc, res) {
    delete res._id;
  },
});

exports.Product = mongoose.model("Product", ProductSchema);
