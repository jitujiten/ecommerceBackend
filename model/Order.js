const mongoose = require("mongoose");
const { Schema } = mongoose;

const OrderSchema = new Schema({
  items: { type: [Schema.Types.Mixed], required: true },
  totalAmount: { type: Number },
  totalItems: { type: Number },
  user: { type: Schema.Types.ObjectId, ref: "User", required: true },
  payMentMethod: { type: String, required: true },
  paymentStatus:{type:String,default: "pending"},
  status: { type: String, default: "pending" },
  selectAddress: { type: Schema.Types.Mixed, required: true },
  dateOfOrder: {type: String},
});

const virtual = OrderSchema.virtual("id");
virtual.get(function () {
  return this._id;
});
OrderSchema.set("toJSON", {
  virtuals: true,
  versionKey: false,
  transform: function (doc, res) {
    delete res._id;
  },
});

exports.Order = mongoose.model("Order", OrderSchema);
