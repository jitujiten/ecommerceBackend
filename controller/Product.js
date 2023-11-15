const { Product } = require("../model/Product");

exports.createProduct = async (req, res) => {
  const newpro = new Product(req.body);
  try {
    const doc = await newpro.save();
    res.status(201).json(doc);
  } catch (err) {
    res.status(400).json(err);
  }
};

exports.fetchAllProducts = async (req, res) => {
  let condition = {};
  if (!req.query.admin) {
    condition.deleted = { $ne: true };
  }

  let query = Product.find(condition);
  let totalProductQuery = Product.find(condition);

  if (req.query.category) {
    query = query.find({ category: {$in:req.query.category.split(',')} });
    totalProductQuery = totalProductQuery.find({
      category: {$in:req.query.category.split(',')},
    });
  }

  if (req.query.brand) {
    query = query.find({ brand: {$in:req.query.brand.split(',')}});
    totalProductQuery = totalProductQuery.find({ brand: {$in:req.query.brand.split(',')} });
  }

  if (req.query._sort && req.query._order) {
    query = query.sort({ [req.query._sort]: req.query._order });
  }

  const TotalDocs = await totalProductQuery.count().exec();

  if (req.query._page && req.query._limit) {
    const pageSize = req.query._limit;
    const page = req.query._page;
    query = query.skip(pageSize * (page - 1)).limit(pageSize);
  }

  try {
    const docs = await query.exec();
    res.set("X-Total-Count", TotalDocs); //set Used for send data in the header
    res.status(200).json(docs);
  } catch (err) {
    res.status(400).json(err);
  }
};

exports.fetchProductById = async (req, res) => {
  try {
    const id = req.params.id;
    const doc = await Product.findById(id);
    res.status(201).json(doc);
  } catch (err) {
    res.status(400).json(err);
  }
};

exports.updateProductById = async (req, res) => {
  try {
    const id = req.params.id;
    const doc = await Product.findByIdAndUpdate(id, req.body, { new: true });
    res.status(201).json(doc);
  } catch (err) {
    res.status(400).json(err);
  }
};
