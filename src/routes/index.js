const express = require('express');
const routerUser = require('./user.routes');
const router = express.Router();

router.use('/users', routerUser)



module.exports = router;