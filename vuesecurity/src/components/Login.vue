<template>
    <div class="hello">
      <input type="email" name="" id="" placeholder="Email" v-model="email" />
      <input
        type="password"
        name=""
        id=""
        placeholder="password"
        v-model="password"
      />
      <input type="submit" value="submit" @click="loginSubmit" />
    </div>
  </template>
  
  <script>
  import axios from "@/api/http.js";
  
  export default {
    name: "SignUp",
    data() {
      return {
        email: null,
        password: null,
      };
    },
    methods: {
      loginSubmit() {
        let saveData = {
          email: this.email,
          password: this.password,
          auth: 0,
        };
  
        axios.post("/cmbapart/user/login", saveData).then((response) => {
          console.log("email : " + response.data.email);
        });
      },
    },
  };
  </script>
  
  <!-- Add "scoped" attribute to limit CSS to this component only -->
  <style scoped>
  h3 {
    margin: 40px 0 0;
  }
  ul {
    list-style-type: none;
    padding: 0;
  }
  li {
    display: inline-block;
    margin: 0 10px;
  }
  a {
    color: #42b983;
  }
  </style>
  