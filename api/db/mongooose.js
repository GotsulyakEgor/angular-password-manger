const mongoose = require('mongoose')

mongoose.Promise = global.Promise;
mongoose.connect('mongodb://localhost:27017/PasswordManager', {useNewUrlParser: true}).then(() => {
    console.log("Connected to MongoDB successfully")
}).catch((e) => {
    console.log("Error while attempting to connect MongoDB");
    console.log(e)
});

module.exports = {
    mongoose
}
