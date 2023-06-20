const EmailCode = require("./EmailCode");
const User = require("./User");

EmailCode.belongsTo(User) //UserId
User.hasOne(EmailCode)