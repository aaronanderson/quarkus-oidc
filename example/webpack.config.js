const path = require('path');
const webpack = require('webpack');


const HtmlWebpackPlugin = require('html-webpack-plugin');

module.exports = {
	mode: 'development',
	entry: './src/main/web/index.tsx',
    
    devtool: "source-map",

    resolve: {
        extensions: [".ts", ".tsx", ".js", ".jsx"]
		},
		

	output: {
		filename: 'quarkus-react.js',
		path: path.resolve(__dirname, 'src/main/resources/META-INF/resources')
	},

	plugins: [new webpack.ProgressPlugin(), new HtmlWebpackPlugin({
	    //inject: false,
	    template: "./src/main/web/index.html",
	    //hash: true,
	    title: "Quarkus React OIDC Example",
	    filename: "index.html",
	    appMountId: "quarkus-container",
	    //favicon: "./src/main/web/assets/fav.png"
	  })],

	module: {
		rules: [      
			{
					test: /\.ts(x?)$/,
					include: [path.resolve(__dirname, 'src/main/web')],
					use: [
							{
									loader: "ts-loader"
							}
					]
			},

			{
					enforce: "pre",
					test: /\.js$/,
					loader: "source-map-loader"
			},
      

			{
        test: /\.(jpg|png)$/,
        use: {
					loader: "file-loader",
					
					 options: {
						name: "assets/[name].[ext]",
    			 },
        }
      },
		]
	},

	optimization: {
		splitChunks: {
			cacheGroups: {
				vendors: {
					priority: -10,
					test: /[\\/]node_modules[\\/]/
				}
			},

			chunks: 'async',
			minChunks: 1,
			minSize: 30000,
			name: true
		}
	},

	/*externals: {
    "react": "React",
    "react-dom": "ReactDOM"
  },*/

	devServer: {
		open: true
	}
};
