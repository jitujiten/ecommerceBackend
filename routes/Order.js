const express = require("express");
const { fetchOrderByUser, CreateOrder, updateOrder, deleteOrder, fetchAllOrders } = require("../controller/Order");


const router = express.Router();

router
  .post("/",CreateOrder)
  .get("/own", fetchOrderByUser)
  .patch("/:id", updateOrder)
  .delete("/:id", deleteOrder)
  .get("/", fetchAllOrders)
 


exports.router = router;
