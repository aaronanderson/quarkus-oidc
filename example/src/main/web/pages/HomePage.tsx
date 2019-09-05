import React from "react";
import axios from 'axios';

interface HomePageProps {

}

interface HomePageState {
	name: string;
	issuer: string;
	claimNames: string[];
	jwtToken: string;
}

export class HomePage extends React.Component<HomePageProps, HomePageState> {

	state = {
		name: "",
		issuer: "",
		claimNames: [],
		jwtToken: ""
	};
 
	render() {
		return (
			<React.Fragment>
				<div className="banner lead">Secured Page</div>

				<div className="container">
					<div className="left-column">
						<p className="lead">OIDC JWT Token Information</p>

						<p>Name: {this.state.name}</p>
						<p>Issuer: {this.state.issuer}</p>
						<p>Available Claim Names:
							{this.state.claimNames.map((value: string, index: number) => {
        						return <li key={index}>{value}</li>
      						})}
							 </p>
						<p>JWT Token: <code>{this.state.jwtToken}</code></p>


					</div>

				</div>



			</React.Fragment>
		);
	}

	async componentDidMount() {
		
		const response = await axios.get(`/oidc/token`);
		this.setState(response.data);
		console.log(response.data);
	}
}